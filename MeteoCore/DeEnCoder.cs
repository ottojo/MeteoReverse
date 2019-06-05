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
        private unsafe struct CipherKeyContainer
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
        /// Lookup table for P-Box
        /// </summary>
        private static readonly uint[] pBoxTable = Secrets.pBoxTable;

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
        private struct DataContainer
        {
            public ByteUInt L_;
            public ByteUInt L;
            public ByteUInt R;

            /// <summary>
            /// Store SBox result (only used by PBox)
            /// </summary>
            public ByteUInt sBoxResult;

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
            Console.WriteLine("S Box building 6-bit-blocks from input data.");
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

            // char[] r = Convert.ToString(output, 2).PadLeft(30, '0').ToCharArray();
            // Console.WriteLine("Done: " + new string(r));
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

            return output;
        }

        /// <summary>
        /// Applies the S-Box.
        /// Result is strangely formatted, this is just for interoperability with existing code.
        /// The goal is to eliminate this function.
        /// </summary>
        /// <param name="input"></param>
        /// <returns>Result of S-Box with a gap in the Data from bits 4 to 7</returns>
        public static ByteUInt formattedSbox(ByteUInt input)
        {
            uint g6 = build6bitGroups(input.FullUint);
            uint s = Sbox(g6);
            ByteUInt r = new ByteUInt();
            r.FullUint = s;
            r.FullUint <<= 4;
            r.FullUint &= 0xFFFFFF0F;
            r.FullUint |= s & 0xF;
            return r;
        }


        /// <summary>
        ///     Ermittelt Wetterdaten aus den entschlüsselten Bytes und prüft auf Korrektheit.
        /// </summary>
        /// <param name="PlainBytes">Array mit den entschlüsselte Bytes.</param>
        /// <returns>Gibt die aus dem Klartextbytes ermittelten Wetterdaten zurück</returns>
        private uint GetMeteoFromPlain(byte[] PlainBytes)
        {
            uint result;
            uint checkSum;
            checkSum = PlainBytes[2] & 0x0Fu;
            checkSum <<= 8;
            checkSum |= PlainBytes[1];
            checkSum <<= 4;
            checkSum |= (uint) (PlainBytes[0] >> 4);

            result = (PlainBytes[0] & 0x0Fu) | 0x10u;
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
                result &= 0x3FFFFF;
                result |= 0x400000;
            }

            return result;
        }


        private unsafe void CopyTimeToByteUint(byte* data, byte* key, ref DataContainer container)
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
        private void ExpandR(ref DataContainer container)
        {
            uint tmp;

            // Use only lower 20 bit (clear previous expansion?)
            container.R.FullUint &= 0x000FFFFF; // clear 0D(4-7),0E

            // Set bits right to left, starting here:
            tmp = 0x00100000; // and set bits form 0B-0D(0-3)
            for (var i = 0; i < 12; i++)
            {
                // last 2 elements in array are 0?
                // -> makes sense, need 10 new bits to expand from 20 to 30
                // why iteration until 12 and not 10?
                if ((container.R.FullUint & expandRTable[i]) != 0)
                    container.R.FullUint |= tmp;
                tmp <<= 1;
            }
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

        public static ByteUInt Pbox(ByteUInt sBoxResult)
        {
            ByteUInt r = new ByteUInt {FullUint = 0xFF000000};
            uint tmp = 0x00000001;
            for (var i = 0; i < 20; i++)
            {
                if ((sBoxResult.FullUint & pBoxTable[i]) != 0)
                {
                    // Set this bit (RTL)
                    r.FullUint |= tmp;
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
                ShiftTimeRight(round, ref container);
                ExpandR(ref container);
                // L' = CompressKey
                container.L_ = CompressKey(container.timeH, container.timeL);

                // (expR XOR compr.Key)
                // XOR expanded R (30 bytes) with compressed key (from time)
                // L' = L' XOR R_Expanded
                container.L_.FullUint ^= container.R.FullUint; // 12-15 XOR 0B-0E


                // reset 4 lowest bits of R expansion
                container.R.Byte2 &= 0x0F; // clear 0D(4-7)

                // Apply SBox to L' (Also reduces L' from 30 to 20 bit)
                container.sBoxResult = formattedSbox(container.L_);

                // Apply PBox to L'
                container.L_ = Pbox(container.sBoxResult);

                // L XOR P-Boxed Round-Key (L')
                container.L_.FullUint ^= container.L.FullUint;

                // L = R
                container.L.FullUint = container.R.FullUint & 0x00FFFFFF;

                // R = L'
                container.R.FullUint = container.L_.FullUint & 0x00FFFFFF;
            } // end of outer loop 1

            container.R.FullUint <<= 4;
            container.L.Byte2 &= 0x0F;
            container.L.Byte2 |= (byte) (container.R.Byte0 & 0xF0);

            //R0B0C0D0E.byte.R0D |= (R08090A.byte.R08 & 0xF0);
            plain[0] = container.L.Byte0;
            plain[1] = container.L.Byte1;
            plain[2] = container.L.Byte2;
            plain[3] = container.R.Byte1;
            plain[4] = container.R.Byte2;

            return plain;
        }

        #endregion
    }
}