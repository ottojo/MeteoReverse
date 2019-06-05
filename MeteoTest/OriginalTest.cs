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

        [TestMethod]
        public unsafe void TestOriginalCopyTimeToByteUint()
        {
            for (int i = 0; i < TestData.CopyTestData.GetLength(0); i++)
            {
                OriginalDeEnCoder.CipherKeyContainer c = new OriginalDeEnCoder.CipherKeyContainer();
                for (int b = 0; b < 10; b++)
                {
                    c.AllBytes[b] = (byte) TestData.CopyTestData[i, b];
                }

                OriginalDeEnCoder.DataContainer expected = new OriginalDeEnCoder.DataContainer();
                expected.R.FullUint = TestData.CopyTestData[i, 10];
                expected.L.FullUint = TestData.CopyTestData[i, 11];
                expected.timeH = (byte) TestData.CopyTestData[i, 12];
                expected.timeL = TestData.CopyTestData[i, 13];

                OriginalDeEnCoder.DataContainer d = new OriginalDeEnCoder.DataContainer();
                OriginalDeEnCoder.CopyTimeToByteUint(c.CipherBytes, c.KeyBytes, ref d);

                Assert.AreEqual(expected.R.FullUint, d.R.FullUint);
                Assert.AreEqual(expected.L.FullUint, d.L.FullUint);
                Assert.AreEqual(expected.timeH, d.timeH);
                Assert.AreEqual(expected.timeL, d.timeL);
            }
        }
    }
}