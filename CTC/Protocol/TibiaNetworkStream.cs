using System;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Xna.Framework;

namespace CTC
{
    class TibiaNetworkStream : PacketStream
    {
        private const int RsaBlockSize = 128;
        private const uint XteaDelta = 0x9E3779B9;

        private readonly Socket socket;
        private readonly string host;
        private readonly int port;
        private bool encryptionEnabled;
        private uint[] xteaRoundKeys;

        public TibiaNetworkStream(string host, int port)
        {
            this.host = host;
            this.port = port;
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.NoDelay = true;
            socket.Connect(host, port);
        }

        public string Name
        {
            get { return host + ":" + port; }
        }

        public bool Poll(GameTime Time)
        {
            if (!socket.Connected)
                return false;

            if (socket.Available < 2)
                return false;

            int packetSize;
            if (!TryPeekPacketSize(out packetSize))
                return false;

            return socket.Available >= packetSize + 2;
        }

        public NetworkMessage Read(GameTime Time)
        {
            if (!Poll(Time))
                return null;

            byte[] payload = ReadPacketPayload();
            if (payload == null)
                return null;

            if (encryptionEnabled)
                payload = DecryptPayload(payload);

            if (payload == null)
                return null;

            NetworkMessage msg = new NetworkMessage(true);
            for (int i = 0; i < payload.Length; ++i)
                msg.AddByte(payload[i]);
            return msg;
        }

        public void Write(NetworkMessage nmsg)
        {
            if (nmsg == null)
                return;

            if (!encryptionEnabled)
            {
                nmsg.WriteTo(socket);
                return;
            }

            byte[] payload = nmsg.GetBytes();
            byte[] encrypted = EncryptPayload(payload);
            SendPacket(encrypted);
        }

        public void SendGameLogin(uint accountNumber, string characterName, string password, ushort clientVersion, ushort clientOS)
        {
            uint[] key = GenerateXteaKey();
            byte[] rsaBlock = BuildGameLoginBlock(key, accountNumber, characterName, password);
            byte[] rsaEncrypted = RsaEncrypt(rsaBlock);

            NetworkMessage msg = new NetworkMessage();
            msg.AddU16(clientOS);
            msg.AddU16(clientVersion);
            for (int i = 0; i < rsaEncrypted.Length; ++i)
                msg.AddByte(rsaEncrypted[i]);

            msg.WriteTo(socket);
            EnableXtea(key);
        }

        public static uint ParseAccountNumber(string accountName, uint fallback)
        {
            uint accountNumber;
            if (UInt32.TryParse(accountName, out accountNumber))
                return accountNumber;

            Log.Warning("Account name must be numeric for 7.72. Using fallback account number " + fallback + ".");
            return fallback;
        }

        private void EnableXtea(uint[] key)
        {
            xteaRoundKeys = ExpandXteaKey(key);
            encryptionEnabled = true;
        }

        private bool TryPeekPacketSize(out int size)
        {
            size = 0;
            try
            {
                byte[] header = new byte[2];
                int read = socket.Receive(header, 0, 2, SocketFlags.Peek);
                if (read < 2)
                    return false;

                size = header[0] | (header[1] << 8);
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
        }

        private byte[] ReadPacketPayload()
        {
            byte[] header = ReadExact(2);
            if (header == null)
                return null;

            int size = header[0] | (header[1] << 8);
            if (size <= 0)
                return null;

            return ReadExact(size);
        }

        private void SendPacket(byte[] payload)
        {
            if (payload == null)
                return;

            ushort size = (ushort)payload.Length;
            byte[] header = new byte[2];
            header[0] = (byte)(size & 0xFF);
            header[1] = (byte)((size >> 8) & 0xFF);

            socket.Send(header);
            socket.Send(payload);
        }

        private byte[] ReadExact(int size)
        {
            byte[] buffer = new byte[size];
            int offset = 0;

            while (offset < size)
            {
                int read = socket.Receive(buffer, offset, size - offset, SocketFlags.None);
                if (read <= 0)
                    return null;

                offset += read;
            }

            return buffer;
        }

        private byte[] EncryptPayload(byte[] payload)
        {
            byte[] withLength = new byte[payload.Length + 2];
            ushort length = (ushort)payload.Length;
            withLength[0] = (byte)(length & 0xFF);
            withLength[1] = (byte)((length >> 8) & 0xFF);
            Buffer.BlockCopy(payload, 0, withLength, 2, payload.Length);

            int padding = (8 - (withLength.Length % 8)) % 8;
            if (padding != 0)
                Array.Resize(ref withLength, withLength.Length + padding);

            byte[] encrypted = (byte[])withLength.Clone();
            XteaEncrypt(encrypted, encrypted.Length, xteaRoundKeys);
            return encrypted;
        }

        private byte[] DecryptPayload(byte[] payload)
        {
            if ((payload.Length % 8) != 0)
                return TryDecryptWithChecksum(payload);

            byte[] decrypted = (byte[])payload.Clone();
            XteaDecrypt(decrypted, decrypted.Length, xteaRoundKeys);

            if (decrypted.Length < 2)
                return null;

            ushort innerLength = (ushort)(decrypted[0] | (decrypted[1] << 8));
            if (innerLength > decrypted.Length - 2)
                return TryDecryptWithChecksum(payload);

            byte[] message = new byte[innerLength];
            Buffer.BlockCopy(decrypted, 2, message, 0, innerLength);
            return message;
        }

        private byte[] TryDecryptWithChecksum(byte[] payload)
        {
            if (payload.Length <= 4)
                return null;

            byte[] encrypted = new byte[payload.Length - 4];
            Buffer.BlockCopy(payload, 4, encrypted, 0, encrypted.Length);

            if ((encrypted.Length % 8) != 0)
                return null;

            byte[] decrypted = (byte[])encrypted.Clone();
            XteaDecrypt(decrypted, decrypted.Length, xteaRoundKeys);

            if (decrypted.Length < 2)
                return null;

            ushort innerLength = (ushort)(decrypted[0] | (decrypted[1] << 8));
            if (innerLength > decrypted.Length - 2)
                return null;

            byte[] message = new byte[innerLength];
            Buffer.BlockCopy(decrypted, 2, message, 0, innerLength);
            return message;
        }

        private static uint[] GenerateXteaKey()
        {
            byte[] keyBytes = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(keyBytes);

            uint[] key = new uint[4];
            for (int i = 0; i < 4; ++i)
                key[i] = BitConverter.ToUInt32(keyBytes, i * 4);

            return key;
        }

        private static uint[] ExpandXteaKey(uint[] key)
        {
            uint[] expanded = new uint[64];

            uint sum = 0;
            uint nextSum = XteaDelta;

            for (int i = 0; i < expanded.Length; i += 2)
            {
                expanded[i] = sum + key[sum & 3];
                expanded[i + 1] = nextSum + key[(nextSum >> 11) & 3];
                sum = nextSum;
                nextSum += XteaDelta;
            }

            return expanded;
        }

        private static void XteaEncrypt(byte[] data, int length, uint[] roundKeys)
        {
            for (int i = 0; i < roundKeys.Length; i += 2)
            {
                for (int j = 0; j < length; j += 8)
                {
                    uint left = (uint)(data[j + 0] | (data[j + 1] << 8) | (data[j + 2] << 16) | (data[j + 3] << 24));
                    uint right = (uint)(data[j + 4] | (data[j + 5] << 8) | (data[j + 6] << 16) | (data[j + 7] << 24));

                    left += ((right << 4 ^ right >> 5) + right) ^ roundKeys[i];
                    right += ((left << 4 ^ left >> 5) + left) ^ roundKeys[i + 1];

                    data[j + 0] = (byte)(left);
                    data[j + 1] = (byte)(left >> 8);
                    data[j + 2] = (byte)(left >> 16);
                    data[j + 3] = (byte)(left >> 24);
                    data[j + 4] = (byte)(right);
                    data[j + 5] = (byte)(right >> 8);
                    data[j + 6] = (byte)(right >> 16);
                    data[j + 7] = (byte)(right >> 24);
                }
            }
        }

        private static void XteaDecrypt(byte[] data, int length, uint[] roundKeys)
        {
            for (int i = roundKeys.Length - 1; i > 0; i -= 2)
            {
                for (int j = 0; j < length; j += 8)
                {
                    uint left = (uint)(data[j + 0] | (data[j + 1] << 8) | (data[j + 2] << 16) | (data[j + 3] << 24));
                    uint right = (uint)(data[j + 4] | (data[j + 5] << 8) | (data[j + 6] << 16) | (data[j + 7] << 24));

                    right -= ((left << 4 ^ left >> 5) + left) ^ roundKeys[i];
                    left -= ((right << 4 ^ right >> 5) + right) ^ roundKeys[i - 1];

                    data[j + 0] = (byte)(left);
                    data[j + 1] = (byte)(left >> 8);
                    data[j + 2] = (byte)(left >> 16);
                    data[j + 3] = (byte)(left >> 24);
                    data[j + 4] = (byte)(right);
                    data[j + 5] = (byte)(right >> 8);
                    data[j + 6] = (byte)(right >> 16);
                    data[j + 7] = (byte)(right >> 24);
                }
            }
        }

        private static byte[] BuildGameLoginBlock(uint[] xteaKey, uint accountNumber, string characterName, string password)
        {
            byte[] block = new byte[RsaBlockSize];
            int offset = 0;

            block[offset++] = 0x00;

            for (int i = 0; i < 4; ++i)
                WriteU32(block, ref offset, xteaKey[i]);

            block[offset++] = 0x00; // gamemaster flag
            WriteU32(block, ref offset, accountNumber);
            WriteString(block, ref offset, characterName);
            WriteString(block, ref offset, password);

            if (offset > block.Length)
                throw new InvalidOperationException("Login payload exceeds RSA block size.");

            FillRandom(block, offset);
            return block;
        }

        private static void WriteU32(byte[] buffer, ref int offset, uint value)
        {
            buffer[offset++] = (byte)(value & 0xFF);
            buffer[offset++] = (byte)((value >> 8) & 0xFF);
            buffer[offset++] = (byte)((value >> 16) & 0xFF);
            buffer[offset++] = (byte)((value >> 24) & 0xFF);
        }

        private static void WriteString(byte[] buffer, ref int offset, string value)
        {
            if (value == null)
                value = string.Empty;

            byte[] bytes = Encoding.ASCII.GetBytes(value);
            ushort length = (ushort)bytes.Length;

            buffer[offset++] = (byte)(length & 0xFF);
            buffer[offset++] = (byte)((length >> 8) & 0xFF);

            Array.Copy(bytes, 0, buffer, offset, bytes.Length);
            offset += bytes.Length;
        }

        private static void FillRandom(byte[] buffer, int offset)
        {
            if (offset >= buffer.Length)
                return;

            byte[] random = new byte[buffer.Length - offset];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(random);

            Array.Copy(random, 0, buffer, offset, random.Length);
        }

        private static byte[] RsaEncrypt(byte[] plaintext)
        {
            if (plaintext.Length != RsaBlockSize)
                throw new ArgumentException("RSA block must be 128 bytes.", "plaintext");

            BigInteger m = ToBigInteger(plaintext);
            BigInteger e = ToBigInteger(RsaExponent);
            BigInteger n = ToBigInteger(RsaModulus);

            BigInteger c = BigInteger.ModPow(m, e, n);
            return FromBigInteger(c, RsaBlockSize);
        }

        private static BigInteger ToBigInteger(byte[] bigEndian)
        {
            byte[] littleEndian = new byte[bigEndian.Length + 1];
            for (int i = 0; i < bigEndian.Length; ++i)
                littleEndian[i] = bigEndian[bigEndian.Length - 1 - i];
            return new BigInteger(littleEndian);
        }

        private static byte[] FromBigInteger(BigInteger value, int size)
        {
            byte[] little = value.ToByteArray();
            int length = little.Length;

            if (length > 1 && little[length - 1] == 0)
                length--;

            byte[] big = new byte[size];
            for (int i = 0; i < length && i < size; ++i)
                big[size - 1 - i] = little[i];

            return big;
        }

        private static readonly byte[] RsaExponent = new byte[] { 0x01, 0x00, 0x01 };

        private static readonly byte[] RsaModulus = new byte[]
        {
            0x9B, 0x64, 0x69, 0x03, 0xB4, 0x5B, 0x07, 0xAC,
            0x95, 0x65, 0x68, 0xD8, 0x73, 0x53, 0xBD, 0x71,
            0x65, 0x13, 0x9D, 0xD7, 0x94, 0x07, 0x03, 0xB0,
            0x3E, 0x6D, 0xD0, 0x79, 0x39, 0x96, 0x61, 0xB4,
            0xA8, 0x37, 0xAA, 0x60, 0x56, 0x1D, 0x7C, 0xCB,
            0x94, 0x52, 0xFA, 0x00, 0x80, 0x59, 0x49, 0x09,
            0x88, 0x2A, 0xB5, 0xBC, 0xA5, 0x8A, 0x1A, 0x1B,
            0x35, 0xF8, 0xB1, 0x05, 0x9B, 0x72, 0xB1, 0x21,
            0x26, 0x11, 0xC6, 0x15, 0x2A, 0xD3, 0xDB, 0xB3,
            0xCF, 0xBE, 0xE7, 0xAD, 0xC1, 0x42, 0xA7, 0x5D,
            0x3D, 0x75, 0x97, 0x15, 0x09, 0xC3, 0x21, 0xC5,
            0xC2, 0x4A, 0x5B, 0xD5, 0x1F, 0xD4, 0x60, 0xF0,
            0x1B, 0x4E, 0x15, 0xBE, 0xB0, 0xDE, 0x19, 0x30,
            0x52, 0x8A, 0x5D, 0x3F, 0x15, 0xC1, 0xE3, 0xCB,
            0xF5, 0xC4, 0x01, 0xD6, 0x77, 0x7E, 0x10, 0xAC,
            0xAA, 0xB3, 0x3D, 0xBE, 0x8D, 0x5B, 0x7F, 0xF5
        };
    }
}
