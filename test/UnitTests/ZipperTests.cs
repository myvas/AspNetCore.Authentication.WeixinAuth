using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using AspNetCore.Authentication.WeixinAuth;

namespace test
{
    public class ZipperTests
    {
        [Fact]
        public async Task Zip_Pass()
        {
            var s = "";
            for (int i = 0; i < 100; i++)
                s += @".redirect=http://weixinoauth.myvas.com/challenge-weixinauth
.xsrf=P-QoagyhhXXBedYnF92z84UEDXlDeS-_m-SRwaldv1w";

            var len1 = s.Length;
            var o = await CompressionExtensions.Zip(s);
            var len2 = o.ToArray().Length;

            Assert.True(len2<len1);

        }

        [Fact]
        public void MathRound_Pass()
        {
            Assert.Equal(9, Math.Round(8.96));
        }
    }
}
