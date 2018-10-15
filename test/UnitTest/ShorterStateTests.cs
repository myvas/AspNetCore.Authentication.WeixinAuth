using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using Myvas.AspNetCore.Authentication.WeixinAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using System.Security.Cryptography;

namespace UnitTest
{
    public class ShorterStateTests
    {
        [Theory]
        [InlineData(true, null)]
        [InlineData(true, "")]
        [InlineData(true, "1234567890123456")]
        [InlineData(true, "12345678901234567")]
        [InlineData(false, "123456789012345678")]
        [InlineData(false, "1234567890123456789")]
        [InlineData(false, "12345678901234567890")]
        [InlineData(false, "123456789012345678901")]
        public void ShorterStateTest(bool expected, string correlationId)
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var properties = new AuthenticationProperties();
            properties.Items[".xrsf"] = correlationId;
            var state = stateFormat.Protect(properties);
            Assert.Equal(expected, state.Length <= 128);
        }

        [Theory]
        [InlineData(true, 1)]
        [InlineData(true, 8)]
        [InlineData(true, 12)]
        [InlineData(false, 13)]
        [InlineData(false, 14)]
        [InlineData(false, 15)]
        [InlineData(false, 16)]
        [InlineData(false, 17)]
        public void ShorterState_GenerateCorrelationId_Test(bool expected, int len)
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var properties = new AuthenticationProperties();

            var cryptoRandom = RandomNumberGenerator.Create();
            var bytes = new byte[len];
            cryptoRandom.GetBytes(bytes);
            var correlationId = Base64UrlTextEncoder.Encode(bytes);

            properties.Items[".xrsf"] = correlationId;
            var state = stateFormat.Protect(properties);
            Assert.Equal(expected, state.Length <= 128);
        }

        [Theory]
        [InlineData(true, 1, 1)]
        [InlineData(false, 1, 32)]
        [InlineData(false, 8, 1)]
        [InlineData(false, 12, 1)]
        public void ShorterStateTest_WhereKeepRedirect(bool expected, int correlationIdGeneratorSize, int redirectUrlLen)
        {
            var stateFormat = new PropertiesDataFormat(new EphemeralDataProtectionProvider(NullLoggerFactory.Instance).CreateProtector("WeixinAuthTest"));
            var properties = new AuthenticationProperties();

            var cryptoRandom = RandomNumberGenerator.Create();
            var bytes = new byte[correlationIdGeneratorSize];
            cryptoRandom.GetBytes(bytes);
            var correlationId = Base64UrlTextEncoder.Encode(bytes);
            properties.Items[".xrsf"] = correlationId;

            var redirectUrl = new string('a', redirectUrlLen);
            properties.Items[".redirect"] = redirectUrl;

            var state = stateFormat.Protect(properties);
            Assert.Equal(expected, state.Length <= 128);
        }

        [Theory]
        [InlineData(false, 1)]
        [InlineData(false, 8)]
        [InlineData(false, 16)]
        [InlineData(false, 32)]
        [InlineData(false, 33)]
        [InlineData(false, 41)]
        [InlineData(false, 42)]
        [InlineData(true, 43)]
        [InlineData(true, 44)]
        [InlineData(true, 48)]
        [InlineData(true, 64)]
        [InlineData(true, 128)]
        [InlineData(true, 256)]
        [InlineData(true, 1024)]
        [InlineData(true, 2048)]
        public async Task Zip_ResultWillBeGood(bool expected, int len)
        {
            var s = new string('a', len);
            var len1 = s.Length;
            var o = await CompressionExtensions.Zip(s);
            var len2 = o.ToArray().Length;

            Assert.Equal(expected, len2 < len1);
        }

        [Fact]
        public void MathRound_Pass()
        {
            Assert.Equal(9, Math.Round(8.96));
        }
    }
}
