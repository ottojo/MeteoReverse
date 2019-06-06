using System;
using System.Runtime.InteropServices;
using MeteoCore;

namespace MeteoSolution
{
    /// <summary>
    ///     Enthält alle Funktionen zum Verschlüsseln und Entschlüsseln der via DCF77 übertragenen Wetterdaten.
    ///     Quelle: meteocrypt_working.c
    /// </summary>
    public class DeEnCoder
    {
        #region Deklarationen, Secrets, Sboxes, etc.

        /// <summary>
        ///     Container zum Konvertieren zwischen 4 Bytes und Uint.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct ByteUInt
        {
            // O: least significant byte
            [FieldOffset(0)] public byte Byte0;

            [FieldOffset(1)] public byte Byte1;

            [FieldOffset(2)] public byte Byte2;

            [FieldOffset(3)] public byte Byte3;

            [FieldOffset(0)] public uint FullUint;
        }

        /// <summary>
        ///     Container zum schnellen Zusammenfassen und Trennen von Key und Cipher.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct CipherKeyContainer
        {
            [FieldOffset(0)] public fixed byte AllBytes[10]; // = new Byte[10];

            [FieldOffset(0)] public fixed byte CipherBytes[5]; // = new Byte[5];

            [FieldOffset(5)] public fixed byte KeyBytes[5]; // = new Byte[5];
        }

        /// <summary>
        /// Lookup table to expand R
        /// </summary>
        private static readonly uint[] expandRTable = Secrets.expandRTable;

        /// <summary>
        ///  Lookup table for key compression
        /// </summary>
        private static readonly uint[] timeCompression1 = Secrets.timeCompression1;

        /// <summary>
        ///  Lookup table for key compression
        /// </summary>
        private static readonly uint[] timeCompression2 = Secrets.timeCompression2;

        /// <summary>
        /// Lookup table for P-Box without weird gap from bits 4 to 7
        /// </summary>
        public static readonly uint[] newpBoxTable = Secrets.PBoxTable;

        /// <summary>
        /// Substitution table for S-Box
        /// </summary>
        private static readonly byte[] sTable1 = Secrets.sTable1;

        /// <summary>
        /// Substitution table for S-Box
        /// </summary>
        private static readonly byte[] sTable2 = Secrets.sTable2;

        /// <summary>
        /// Substitution table for S-Box
        /// </summary>
        private static readonly byte[] sTable3 = Secrets.sTable3;

        /// <summary>
        ///     Container, wich contains all former global vars
        /// </summary>
        public struct DataContainer
        {
            public ByteUInt L;
            public ByteUInt R;

            public byte timeH;
            public uint timeL;
        }

        #endregion

        #region Public Methoden

        /// <summary>
        ///     Entschlüsselt einen Datensatz.
        /// </summary>
        /// <param name="encodedDataset">Verschlüsselte Wetterdaten in binärer Form.</param>
        /// <returns>Gibt die entschlüsselten Wetterdaten in binärer Form (untere 22 Bit + 2 Bit Status) zurück.</returns>
        public unsafe uint DecodeDataset(byte[] encodedDataset)
        {
            var dataCiperKey = new CipherKeyContainer();
            for (var i = 0; i < 10; i++)
                if (i < encodedDataset.Length)
                    dataCiperKey.AllBytes[i] = encodedDataset[i];
                else
                    dataCiperKey.AllBytes[i] = 0;

            byte[] plain;

            plain = Decrypt(dataCiperKey.CipherBytes, dataCiperKey.KeyBytes);
            return GetMeteoFromPlain(plain);
        }

        /// <summary>
        /// Entschlüsselt einen Datensatz.
        /// </summary>
        /// <param name="encodedDataset">Verschlüsselte Wetterdaten in Form eines Strings (Big-Endian).</param>
        /// <returns>Gibt die entschlüsselten Wetterdaten in Form eines Strings (Big-Endian) zurück.</returns>
        public string DecodeDataset(string encodedDataset)
        {
            int uiBitCnt, uiCnt;
            byte ucTemp = 0;
            byte[] dataCiperKey = new byte[10];
            uint meteoResult;
            encodedDataset = encodedDataset.PadRight(82, '0');
            uiBitCnt = 0;
            for (uiCnt = 1; uiCnt < 82; uiCnt++)
            {
                if (uiCnt != 7)
                {
                    ucTemp >>= 1;
                    uiBitCnt++;
                    if (encodedDataset[uiCnt] == '1')
                        ucTemp |= 0b10000000;
                    if (uiBitCnt % 8 == 0)
                        dataCiperKey[uiBitCnt / 8 - 1] = ucTemp;
                }
            }

            Console.Write("Decoding {");
            for (int i = 0; i < dataCiperKey.Length; i++)
            {
                Console.Write($"{dataCiperKey[i]}, ");
            }

            Console.WriteLine("}");
            meteoResult = DecodeDataset(dataCiperKey);

            char[] result = Convert.ToString(meteoResult, 2).PadLeft(24, '0').ToCharArray();
            Array.Reverse(result);

            return new string(result);
        }

        #endregion

        #region Private Methoden

        /// <summary>
        /// This arranges 30 bits into 5 6-bit-groups for use with S-Box.
        /// Every third 2-bit-group comes the bits 20 to 30.
        /// </summary>
        public static uint build6bitGroups(uint input)
        {
            uint output = 0;
            int lowIndex = 0;
            int highIndex = 20;
            for (int i = 0; i < 30; i++)
            {
                if ((i + 1) % 6 == 0 || (i + 2) % 6 == 0)
                {
                    // Console.WriteLine("Getting bit " + i + " from " + highIndex);
                    output |= ((input >> highIndex) & 0b1) << i;
                    highIndex++;
                }
                else
                {
                    // Console.WriteLine("Getting bit " + i + " from " + lowIndex);
                    output |= ((input >> lowIndex) & 0b1) << i;
                    lowIndex++;
                }
            }

            return output;
        }

        /// <summary>
        /// Applies substitution to data.
        /// S5 is applied to the lowest 6 bit and so on.
        /// The result of S5 is NOT stored in the lowest 4 bit in the result.
        /// The order of the resulting 4-bit segments seems arbitrarily chosen.
        /// The substitution table contains bytes, S4 and S2 use the highest 4 bits.
        /// </summary>
        /// <returns>Substituted and rearranged data (20bit)</returns>
        public static uint Sbox(uint groups6bit)
        {
            uint output = 0;
            // S5 (store at offset 12)
            output |= (uint) ((sTable1[groups6bit & 0x3F] & 0xF) << 12);

            // S4 Use bits 3 to 7 here (store at offset 16)
            output |= (uint) ((sTable1[(groups6bit >> 6) & 0x3F] & 0xF0) << 12);

            // S3 (store at offset 4)
            output |= (uint) ((sTable2[(groups6bit >> 12) & 0x3F] & 0xF) << 4);

            // S2 Use bits 3 to 7 here (store at offset 8)
            output |= (uint) ((sTable2[(groups6bit >> 18) & 0x3F] & 0xF0) << 4);

            // S1 (store at offset 0)
            output |= (uint) (sTable3[(groups6bit >> 24) & 0x3F] & 0xF);

            Console.WriteLine($"Sbox({groups6bit})={output}");

            return output;
        }


        /// <summary>
        ///     Ermittelt Wetterdaten aus den entschlüsselten Bytes und prüft auf Korrektheit.
        /// </summary>
        /// <param name="PlainBytes">Array mit den entschlüsselte Bytes. (40bit, 5byte)</param>
        /// <returns>Gibt die aus dem Klartextbytes ermittelten Wetterdaten zurück</returns>
        public static uint GetMeteoFromPlain(byte[] PlainBytes)
        {
            // if R = 0x01234, L = 0x56789,
            // the input will be [0x89 0x67 0x45 0x23 0x01]
            uint result;
            uint checkSum;
            checkSum = PlainBytes[2] & 0x0Fu;
            checkSum <<= 8;
            checkSum |= PlainBytes[1];
            checkSum <<= 4;
            checkSum |= (uint) (PlainBytes[0] >> 4);

            result = (PlainBytes[0] & 0xFu) | 0b10000u;
            result <<= 8;
            result |= PlainBytes[4];
            result <<= 8;
            result |= PlainBytes[3];
            result <<= 4;
            result |= (uint) (PlainBytes[2] >> 4);

            if (checkSum != 0x2501)
            {
                result = 0x200001;
            }
            else
            {
                result &= 0x3FFFFF; // truncate to 22bit
                result |=
                    0b10000000000000000000000; // set bit 22 -> will be ...10 after reversing to signal good conversion
            }

            return result;
        }


        public static unsafe void CopyTimeToByteUint(byte* data, byte* key, ref DataContainer container)
        {
            for (var i = 0; i < 4; i++)
            {
                container.timeL <<= 8;
                container.timeL |= key[3 - i];
            }

            container.timeH = key[4];

            // copy R
            container.R.Byte0 = data[2];
            container.R.Byte1 = data[3];
            container.R.Byte2 = data[4];
            container.R.FullUint >>= 4;

            // copy L
            container.L.Byte0 = data[0];
            container.L.Byte1 = data[1];
            container.L.Byte2 = (byte) (data[2] & 0x0F);
        }


        private void ShiftTimeRight(int round, ref DataContainer container)
        {
            int count;
            byte tmp;

            if (round == 16 || round == 8 || round == 7 || round == 3)
                count = 2;
            else
                count = 1;

            while (count-- != 0)
            {
                // Rotate low 20 bit right
                tmp = 0;
                if ((container.timeL & 0x00100000) != 0) // save time bit 20 (first bit that should really belong to H)
                    tmp = 1;
                container.timeL &= 0xFFEFFFFF;
                if ((container.timeL & 1) != 0)
                    container.timeL |= 0x00100000; // copy time bit 0 to time bit 20
                container.timeL >>= 1; // time >>= 1

                if ((container.timeH & 1) != 0)
                    container.timeL |= 0x80000000;
                container.timeH >>= 1;
                if (tmp != 0)
                    container.timeH |= 0x80; // insert time bit 20 to time bit 39
            }
        }

        /// <summary>
        ///    expands R from 20 to 30 bit
        /// </summary>
        public static ByteUInt ExpandR(ByteUInt R)
        {
            uint tmp;

            // Set bits right to left, starting here:
            tmp = 0x00100000; // and set bits form 0B-0D(0-3)
            for (var i = 0; i < 10; i++)
            {
                if ((R.FullUint & expandRTable[i]) != 0)
                    R.FullUint |= tmp;
                tmp <<= 1;
            }

            return R;
        }

        /// <summary>
        /// Compress 40 bit time to 30 bit key (stored in L')
        /// </summary>
        private ByteUInt CompressKey(byte timeH, uint timeL)
        {
            ByteUInt L_ = new ByteUInt();
            uint tmp;

            L_.FullUint = 0; // clear 12-15
            tmp = 0x00000001; // and set bits from 16-1A (time)
            for (var i = 0; i < 30; i++)
            {
                if ((timeL & timeCompression1[i]) != 0 ||
                    (timeH & timeCompression2[i]) != 0)
                    L_.FullUint |= tmp;
                tmp <<= 1;
            }

            return L_;
        }

        public static uint Pbox(uint sBoxResult)
        {
            uint r = 0;
            uint tmp = 0x00000001;
            for (var i = 0; i < 20; i++)
            {
                if ((sBoxResult & newpBoxTable[i]) != 0)
                {
                    // Set this bit (RTL)
                    r |= tmp;
                }

                tmp <<= 1;
            }

            return r;
        }

        /// <summary>
        ///     DECRYPTION
        /// </summary>
        /// <param name="cipher"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        private unsafe byte[] Decrypt(byte* cipher, byte* key)
        {
            var container = new DataContainer();

            var plain = new byte[5];
            CopyTimeToByteUint(cipher, key, ref container);

            // OUTER LOOP 1 (16 Rounds)
            for (var round = 16; round > 0; round--)
            {
                Console.WriteLine($"Round {round}: L={container.L.FullUint:X}, R={container.R.FullUint:X}");
                Console.WriteLine($"timeH=0x{container.timeH:x}, timeL=0x{container.timeL:x}");

                ShiftTimeRight(round, ref container);

                Console.WriteLine($"Rotated Time. timeH=0x{container.timeH:x}, timeL=0x{container.timeL:x}");

                ByteUInt compressedKey = CompressKey(container.timeH, container.timeL);
                Console.WriteLine($"Compressed key: 0x{compressedKey.FullUint:x}");


                uint expandedR = ExpandR(container.R).FullUint;
                Console.WriteLine($"Expanded R: 0x{expandedR:x}");

                uint sboxInput = compressedKey.FullUint ^ expandedR;


                uint bit6Group = build6bitGroups(sboxInput);
                Console.WriteLine($"Built 6bit groups: {bit6Group:x}");

                uint sboxresult = Sbox(bit6Group);
                Console.WriteLine($"S Box result: {sboxresult:x}");


                uint pboxResult = Pbox(sboxresult);
                Console.WriteLine($"Applied f: {pboxResult:x}");

                pboxResult ^= container.L.FullUint;

                // L = R
                container.L.FullUint = container.R.FullUint;

                // R = L'
                container.R.FullUint = pboxResult;
            }

            Console.WriteLine($"Decrypted R = {container.R.FullUint}, L = {container.L.FullUint}");

            // 4 bits from R get moved to L
            container.R.FullUint <<= 4;
            container.L.Byte2 &= 0x0F;
            container.L.Byte2 |= (byte) (container.R.Byte0 & 0xF0);

            plain[0] = container.L.Byte0;
            plain[1] = container.L.Byte1;
            plain[2] = container.L.Byte2;
            plain[3] = container.R.Byte1;
            plain[4] = container.R.Byte2;

            for (int i = 0; i < 5; i++)
            {
                Console.WriteLine($"plain[{i}] = 0x{plain[i]:X}");
            }

            return plain;
        }

        #endregion
    }
}