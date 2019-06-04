using System;
using System.Runtime.InteropServices;

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
        private struct ByteUInt
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
        ///     bit pattern for 0D,0E from 0B-0D
        /// </summary>
        /// used for expanding R
        private readonly uint[] expandRTable = new uint[12]
        {
        };

        /// <summary>
        ///     12-15 from 16-19 (time)
        /// </summary>
        private readonly uint[] timeCompression1 = new uint[30]
        {



        };

        /// <summary>
        ///     bit pattern for 12-15 from 1A (time2)
        /// </summary>
        private readonly uint[] timeCompression2 = new uint[30]
        {



        };

        /// <summary>
        ///     12-14 from 1C-1E (result from F)
        ///     Why is this 24bit long? quartet 1 always 0 as expected
        ///     (Due to output format of S-Box)
        /// </summary>
        private readonly uint[] pBoxTable = new uint[20]
        {


        };

        /// <summary>
        ///     bit pattern for 12-15 from 16-19 (1/3)
        /// </summary>
        private readonly byte[] sTable1 =
        {
        };

        /// <summary>
        ///     bit pattern for 12-15 from 16-19 (2/3)
        /// </summary>
        private readonly byte[] sTable2 =
        {
        };

        /// <summary>
        ///     bit pattern for 12-15 from 16-19 (3/3)
        /// </summary>
        private readonly byte[] sTable3 =
        {
        };

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
        /// <param name="container"></param>
        private void CompressKey(ref DataContainer container)
        {
            uint tmp;

            container.L_.FullUint = 0; // clear 12-15
            tmp = 0x00000001; // and set bits from 16-1A (time)
            for (var i = 0; i < 30; i++)
            {
                if ((container.timeL & timeCompression1[i]) != 0 ||
                    (container.timeH & timeCompression2[i]) != 0)
                    container.L_.FullUint |= tmp;
                tmp <<= 1;
            }
        }

        private void DoSbox(ref DataContainer container)
        {
            byte helper; //mByteR1B;

            helper = container.L_.Byte3; // R1B = R15;
            container.L_.Byte3 = container.L_.Byte2; // R15 = R14

            // 5 S-Boxen (Each 6 -> 4 bit)
            for (var i = 5; i > 0; i--)
            {
                if (i == 2 || i == 4) // round 4,2
                {
                    byte tmpNew;
                    // Swap left and right half of last byte in L'
                    tmpNew = (byte) (container.L_.Byte0 >> 4);
                    tmpNew |= (byte) ((container.L_.Byte0 & 0x0f) << 4);
                    container.L_.Byte0 = tmpNew;
                }

                byte roundResult;

                container.L_.Byte3 &= 0xF0; // Reset lowest 4 bit in L_3
                roundResult = (byte) ((container.L_.Byte0 & 0x0F) | container.L_.Byte3);


                // Substitution? last 4 in L_0 + highest 4 in L_3 (previously set to L_2) -> table[tmp]?
                // 0x3F: last 6 bit set
                // Round 4,5
                if (i == 4 || i == 5)
                {
                    roundResult = sTable1[roundResult & 0x3F];
                }

                // Round 2, 3
                if (i == 2 || i == 3)
                {
                    roundResult = sTable2[roundResult & 0x3F];
                }

                // Round 1
                else if (i == 1)
                {
                    roundResult = sTable3[roundResult & 0x3F];
                }

                // done substituting roundResult

                if ((i & 1) != 0)
                {
                    // Rounds 5, 3, 1: write lowest 4 bits of tmp to B0
                    container.sBoxResult.Byte0 = (byte) (roundResult & 0x0F);
                }
                else
                {
                    // Rounds 4, 2: write hightest 4 bits of tmp to B0
                    container.sBoxResult.Byte0 |= (byte) (roundResult & 0xF0);
                }

                if ((i & 1) == 0) // copy 14->13->12, 1C->1E->1D
                {
                    // Rounds 4, 2:
                    // Rotate L' right, keep highest byte
                    byte tmpByte3 = container.L_.Byte3;
                    tmpByte3 = container.L_.Byte3;
                    container.L_.FullUint >>= 8;
                    container.L_.Byte3 = tmpByte3;

                    // shift this left
                    container.sBoxResult.FullUint <<= 8;
                }

                // ROTATE L'3 (not shift, rotate!)
                // TODO help is original B3, but B3 is now B2. This does not
                //  rotate correctly?

                // shift B3 (old B2) right, but fill with old B3
                container.L_.Byte3 >>= 1; // rotate R1B>R15 twice

                if ((helper & 1) != 0)
                {
                }

                helper >>= 1;

                // ROTATE L'3 (not shift, rotate!)
                container.L_.Byte3 >>= 1;
                if ((helper & 1) != 0)
                {
                    container.L_.Byte3 |= 0x80;
                }

                helper >>= 1;
            }
        }

        /// <summary>
        /// Apply PBox: read only from sBoxResult
        /// </summary>
        /// <param name="container"></param>
        private void DoPbox(ref DataContainer container)
        {
            container.L_.FullUint = 0xFF000000; // clear lowest 24 bit // why not 20? should not matter...
            uint tmp = 0x00000001; // and set bits from 1C-1E (result from F)
            for (var i = 0; i < 20; i++)
            {
                if ((container.sBoxResult.FullUint & pBoxTable[i]) != 0)
                {
                    // Set this bit (RTL)
                    container.L_.FullUint |= tmp;
                }

                tmp <<= 1;
            }
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
                CompressKey(ref container);

                // (expR XOR compr.Key)
                // XOR expanded R (30 bytes) with compressed key (from time)
                // L' = L' XOR R_Expanded
                container.L_.FullUint ^= container.R.FullUint; // 12-15 XOR 0B-0E


                // reset 4 lowest bits of R expansion
                container.R.Byte2 &= 0x0F; // clear 0D(4-7)

                // Apply SBox to L' (Also reduces L' from 30 to 20 bit)
                DoSbox(ref container);

                // Apply PBox to L'
                DoPbox(ref container);

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