using MeteoSolution;

namespace MeteoCore
{
    class Program
    {
        static void Main(string[] args)
        {
            new DeEnCoder().DecodeDataset(
                "0111011011010111001001100101001111000001010100000000000000110000000110010010011000");
        }
    }
}