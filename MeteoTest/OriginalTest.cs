using MeteoOriginal;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace MeteoTest
{
    [TestClass]
    public class OriginalTest
    {
        [TestMethod]
        public void TestOriginalFull()
        {
            OriginalDeEnCoder d = new OriginalDeEnCoder();
            for (int i = 0; i < TestData.FullTestData.GetLength(0); i++)
            {
                Assert.AreEqual(d.DecodeDataset(TestData.FullTestData[i, 0]), TestData.FullTestData[i, 1]);
            }
        }

        [TestMethod]
        public void TestOriginalSBox()
        {
            for (int i = 0; i < TestData.SBoxTestData.GetLength(0); i++)
            {
                OriginalDeEnCoder.ByteUInt input = new OriginalDeEnCoder.ByteUInt();
                input.FullUint = TestData.SBoxTestData[i, 0];
                Assert.AreEqual(OriginalDeEnCoder.DoSbox(input).FullUint, TestData.SBoxTestData[i, 1]);
            }
        }
        
        [TestMethod]
        public void TestOriginalPBox()
        {
            for (int i = 0; i < TestData.PBoxTestData.GetLength(0); i++)
            {
                OriginalDeEnCoder.ByteUInt input = new OriginalDeEnCoder.ByteUInt();
                input.FullUint = TestData.PBoxTestData[i, 0];
                Assert.AreEqual(OriginalDeEnCoder.DoPbox(input).FullUint, TestData.PBoxTestData[i, 1]);
            }
        }
    }
}