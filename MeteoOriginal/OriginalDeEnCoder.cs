using System;
using System.Runtime.InteropServices;
using MeteoCore;

namespace MeteoOriginal
{
    /// <summary>
    ///     Enthält alle Funktionen zum Verschlüsseln und Entschlüsseln der via DCF77 übertragenen Wetterdaten.
    ///     Quelle: meteocrypt_working.c
    /// </summary>
    public class OriginalDeEnCoder
    {
        #region Deklarationen, Secrets, Sboxes, etc.

        /// <summary>
        ///     Container zum Konvertieren zwischen 4 Bytes und Uint.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct ByteUInt
        {
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
        ///     bit pattern for 0D,0E from 0B-0D
        /// </summary>
        private readonly uint[] mUintArrBitPattern12 = Secrets.expandRTable;

        /// <summary>
        ///     12-15 from 16-19 (time)
        /// </summary>
        private readonly uint[] mUintArrBitPattern30_1 = Secrets.timeCompression1;

        /// <summary>
        ///     bit pattern for 12-15 from 1A (time2)
        /// </summary>
        private readonly uint[] mUintArrBitPattern30_2 = Secrets.timeCompression2;

        /// <summary>
        ///     12-14 from 1C-1E (result from F)
        /// </summary>
        private static readonly uint[] mUintArrBitPattern20 = Secrets.pBoxTable;

        /// <summary>
        ///     bit pattern for 12-15 from 16-19 (1/3)
        /// </summary>
        private static readonly byte[] mByteArrLookupTable1C_1 = Secrets.sTable1;

        /// <summary>
        ///     bit pattern for 12-15 from 16-19 (2/3)
        /// </summary>
        private static readonly byte[] mByteArrLookupTable1C_2 = Secrets.sTable2;

        /// <summary>
        ///     bit pattern for 12-15 from 16-19 (3/3)
        /// </summary>
        private static readonly byte[] mByteArrLookupTable1C_3 = Secrets.sTable3;

        /// <summary>
        ///     Container, wich contains all former global vars
        /// </summary>
        public struct DataContainer
        {
            /// <summary>
            ///     Registers R12 to R15
            /// </summary>
            public ByteUInt L_; // = new ByteUInt();

            /// <summary>
            ///     Registers R08 to R0A
            /// </summary>
            public ByteUInt L; // = new ByteUInt();

            /// <summary>
            ///     Registers R0B to R0E
            /// </summary>
            public ByteUInt R; // = new ByteUInt();

            /// <summary>
            ///     Registers R1C to R1E
            /// </summary>
            public ByteUInt sBoxResult; // = new ByteUInt();

            public byte timeH; //, mByteR1B;
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
        ///     Entschlüsselt einen Datensatz.
        /// </summary>
        /// <param name="encodedDataset">Verschlüsselte Wetterdaten in Form eines Strings (Big-Endian).</param>
        /// <returns>Gibt die entschlüsselten Wetterdaten in Form eines Strings (Big-Endian) zurück.</returns>
        public string DecodeDataset(string encodedDataset)
        {
            int uiBitCnt, uiCnt;
            byte ucTemp = 0;
            var dataCiperKey = new byte[10];
            uint meteoResult;
            encodedDataset = encodedDataset.PadRight(82, '0');
            uiBitCnt = 0;
            for (uiCnt = 1; uiCnt < 82; uiCnt++)
                if (uiCnt != 7)
                {
                    ucTemp = (byte) (ucTemp >> 1);
                    if (encodedDataset[uiCnt] == '1')
                        ucTemp |= 0x80;
                    uiBitCnt++;
                    if ((uiBitCnt & 7) == 0)
                        dataCiperKey[(uiBitCnt >> 3) - 1] = ucTemp;
                }

            meteoResult = DecodeDataset(dataCiperKey);

            var result = Convert.ToString(meteoResult, 2).PadLeft(24, '0').ToCharArray();
            Array.Reverse(result);

            return new string(result);
        }

        #endregion

        #region Private Methoden

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
                tmp = 0;
                if ((container.timeL & 0x00100000) != 0) // save time bit 20
                    tmp = 1;

                container.timeL &= 0xFFEFFFFF;
                if ((container.timeL & 1) != 0)
                    container.timeL |= 0x00100000; // copy time bit 0 to time bit 19
                container.timeL >>= 1; // time >>= 1

                if ((container.timeH & 1) != 0)
                    container.timeL |= 0x80000000;
                container.timeH >>= 1;
                if (tmp != 0)
                    container.timeH |= 0x80; // insert time bit 20 to time bit 39
            }
        }

        private void ExpandR(ref DataContainer container)
        {
            uint tmp;

            container.R.FullUint &= 0x000FFFFF; // clear 0D(4-7),0E
            tmp = 0x00100000; // and set bits form 0B-0D(0-3)
            for (var i = 0; i < 12; i++)
            {
                if ((container.R.FullUint & mUintArrBitPattern12[i]) != 0)
                    container.R.FullUint |= tmp;
                tmp <<= 1;
            }
        }

        private void CompressKey(ref DataContainer container)
        {
            uint tmp;

            container.L_.FullUint = 0; // clear 12-15
            tmp = 0x00000001; // and set bits from 16-1A (time)
            for (var i = 0; i < 30; i++)
            {
                if ((container.timeL & mUintArrBitPattern30_1[i]) != 0 ||
                    (container.timeH & mUintArrBitPattern30_2[i]) != 0)
                    container.L_.FullUint |= tmp;
                tmp <<= 1;
            }
        }


        public static ByteUInt DoSbox(ByteUInt L)
        {
            byte tmp, helper; //mByteR1B;

            ByteUInt result = new ByteUInt();

            result.FullUint = 0;

            helper = L.Byte3; // R1B = R15;
            L.Byte3 = L.Byte2; // R15 = R14

            // INNER LOOP
            for (var i = 5; i > 0; i--)
            {
                if ((i & 1) == 0) // round 4,2
                {
                    tmp = (byte) (L.Byte0 >> 4); // swap R12
                    tmp |= (byte) ((L.Byte0 & 0x0f) << 4);
                    L.Byte0 = tmp;
                }

                L.Byte3 &= 0xF0; // set R1C
                tmp = (byte) ((L.Byte0 & 0x0F) | L.Byte3);

                if ((i & 4) != 0)
                    tmp = mByteArrLookupTable1C_1[tmp & 0x3F];

                if ((i & 2) != 0)
                    tmp = mByteArrLookupTable1C_2[tmp & 0x3F];

                else if (i == 1)
                    tmp = mByteArrLookupTable1C_3[tmp & 0x3F];

                if ((i & 1) != 0)
                    result.Byte0 = (byte) (tmp & 0x0F);
                else
                    result.Byte0 |= (byte) (tmp & 0xF0);

                if ((i & 1) == 0) // copy 14->13->12, 1C->1E->1D
                {
                    tmp = L.Byte3;
                    L.FullUint >>= 8;
                    L.Byte3 = tmp;
                    result.FullUint <<= 8;
                }

                L.Byte3 >>= 1; // rotate R1B>R15 twice
                if ((helper & 1) != 0)
                    L.Byte3 |= 0x80;
                helper >>= 1;

                L.Byte3 >>= 1;
                if ((helper & 1) != 0)
                    L.Byte3 |= 0x80;
                helper >>= 1;
            } // end of inner loop

            return result;
        }

        // Read from: sboxresult
        // write to: L
        public static ByteUInt DoPbox(ByteUInt sBoxResult)
        {
            uint tmp;
            ByteUInt L = new ByteUInt();

            L.FullUint = 0xFF000000; // clear 12-14
            tmp = 0x00000001; // and set bits from 1C-1E (result from F)
            for (var i = 0; i < 20; i++)
            {
                if ((sBoxResult.FullUint & mUintArrBitPattern20[i]) != 0)
                    L.FullUint |= tmp;
                tmp <<= 1;
            }

            return L;
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

            //uint ulTemp;
            //uiCnt, uiILCnt, , uiOL2Cnt, uiBitCnt
            //byte ucOL2Pat, ucTemp;
            var plain = new byte[5];
            CopyTimeToByteUint(cipher, key, ref container);

            // OUTER LOOP 1
            for (var i = 16; i > 0; i--)
            {
                ShiftTimeRight(i, ref container);
                ExpandR(ref container);
                CompressKey(ref container);

                // expR XOR compr.Key
                container.L_.FullUint ^= container.R.FullUint; // 12-15 XOR 0B-0E
                container.R.Byte2 &= 0x0F; // clear 0D(4-7)

                container.sBoxResult = DoSbox(container.L_);
                container.L_ = DoPbox(container.sBoxResult);

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