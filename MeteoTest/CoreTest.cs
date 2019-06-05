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
        public unsafe void TestCoreCopyTimeToByteUint()
        {
            for (int i = 0; i < TestData.CopyTestData.GetLength(0); i++)
            {
                DeEnCoder.CipherKeyContainer c = new DeEnCoder.CipherKeyContainer();
                for (int b = 0; b < 10; b++)
                {
                    c.AllBytes[b] = (byte) TestData.CopyTestData[i, b];
                }

                DeEnCoder.DataContainer expected = new DeEnCoder.DataContainer();
                expected.R.FullUint = TestData.CopyTestData[i, 10];
                expected.L.FullUint = TestData.CopyTestData[i, 11];
                expected.timeH = (byte) TestData.CopyTestData[i, 12];
                expected.timeL = TestData.CopyTestData[i, 13];

                DeEnCoder.DataContainer d = new DeEnCoder.DataContainer();
                DeEnCoder.CopyTimeToByteUint(c.CipherBytes, c.KeyBytes, ref d);

                Assert.AreEqual(expected.R.FullUint, d.R.FullUint);
                Assert.AreEqual(expected.L.FullUint, d.L.FullUint);
                Assert.AreEqual(expected.timeH, d.timeH);
                Assert.AreEqual(expected.timeL, d.timeL);
            }
        }

        [TestMethod]
        public void TestCoreExpandR()
        {
            for (int i = 0; i < TestData.ExpandRData.GetLength(0); i++)
            {
                DeEnCoder.ByteUInt b = new DeEnCoder.ByteUInt {FullUint = TestData.ExpandRData[i, 0]};
                Assert.AreEqual(TestData.ExpandRData[i, 1], DeEnCoder.ExpandR(b).FullUint);
            }
        }
    }
}