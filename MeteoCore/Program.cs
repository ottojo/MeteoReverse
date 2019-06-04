using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using MeteoSolution;

namespace MeteoCore
{
    class Program
    {
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
        
        static void Main(string[] args)
        {


            ByteUInt bu = new ByteUInt();
            bu.FullUint = 7;
            bu.Byte1 = 1;
            bu.FullUint >>= 1;
            Console.WriteLine("b0: {0} b1: {1} b2: {2} b3: {3}", bu.Byte0, bu.Byte1, bu.Byte2, bu.Byte3);


            DeEnCoder d = new DeEnCoder();

            Console.WriteLine(
                d.DecodeDataset("0000010000111100001110111011111000001110101010000000000000110000000110010010011000"));

            byte[] data =
            {
                0b00001000, 0b11110000, 0b11101110, 0b11111000, 0b00111010, 0b10100000, 0b00000000, 0b11000000,
                0b01100100, 0b10011000
            };

            for (int i = 0; i < data.Length; i++)
            {
                byte tmp = 0;
                for (byte m = 1; m > 0; m <<= 1)
                {
                    tmp <<= 1;
                    if ((data[i] & m) != 0)
                    {
                        tmp |= 1;
                    }
                }

                data[i] = tmp;
            }

            uint b = d.DecodeDataset(data);
            char[] r = Convert.ToString(b, 2).PadLeft(24, '0').ToCharArray();
            Array.Reverse(r);
            Console.WriteLine(r);
        }
    }
}