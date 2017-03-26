using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace test
{
    public class DotNetCoreTheories
    {
        [Theory]
        [InlineData(3)]
        [InlineData(5)]
        [InlineData(7)]
        [InlineData(9)]
        public void Odd_Pass(int value)
        {
            Assert.Equal(true, IsOdd(value));
        }

        [Theory]
        [InlineData(-3)]
        [InlineData(-5)]
        [InlineData(-7)]
        [InlineData(-9)]
        public void NegetiveOdd_Pass(int value)
        {
            Assert.Equal(true, !IsOdd(value));
        }

        public bool IsOdd(int value)
        {
            return value % 2 == 1;
        }
    }
}
