using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests
{
    public class DotNetCoreFacts
    {
        [Fact]
        public void MathTruncate_Pass()
        {
            Assert.Equal(8, Math.Truncate(8.96));
        }

        [Fact]
        public void MathRound_Pass()
        {
            Assert.Equal(9, Math.Round(8.96));
        }
    }
}
