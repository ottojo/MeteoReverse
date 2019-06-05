using System;
using MeteoOriginal;
using MeteoSolution;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace MeteoTest
{
    [TestClass]
    public class CoreTest
    {
        [TestMethod]
        public void TestCoreFull()
        {
            DeEnCoder d = new DeEnCoder();
            for (int i = 0; i < TestData.FullTestData.GetLength(0); i++)
            {
                Assert.AreEqual(d.DecodeDataset(TestData.FullTestData[i, 0]), TestData.FullTestData[i, 1]);
            }
        }

        [TestMethod]
        public void TestCoreSBox()
        {
            for (int i = 0; i < TestData.SBoxTestData.GetLength(0); i++)
            {
                DeEnCoder.ByteUInt input = new DeEnCoder.ByteUInt();
                input.FullUint = TestData.SBoxTestData[i, 0];
                Assert.AreEqual(DeEnCoder.formattedSbox(input).FullUint, TestData.SBoxTestData[i, 1]);
            }
        }
        
        [TestMethod]
        public void TestCorePBox()
        {
            for (int i = 0; i < TestData.PBoxTestData.GetLength(0); i++)
            {
                DeEnCoder.ByteUInt input = new DeEnCoder.ByteUInt();
                input.FullUint = TestData.PBoxTestData[i, 0];
                Assert.AreEqual(DeEnCoder.Pbox(input).FullUint, TestData.PBoxTestData[i, 1]);
            }
        }
    }
}