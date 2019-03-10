using Myvas.AspNetCore.Authentication;
using Myvas.AspNetCore.Authentication.QQConnect;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Xunit;

namespace UnitTest
{
    public class QQConnectScopesTests
    {
        private class ScopeTester
        {
            public ICollection<string> Scope { get; } = new List<string>();

            public override string ToString()
            {
                return string.Join(",", Scope);
            }
        }

        [Fact]
        public void Scope_TryAdd_One_Test()
        {
            var test = new ScopeTester();
            Assert.Empty(test.Scope);

            test.Scope.Add("1");
            Assert.Equal("1", test.ToString());

            QQConnectScopes.TryAdd(test.Scope, "2".Split(","));
            Assert.Equal("1,2", test.ToString());

            QQConnectScopes.TryAdd(test.Scope, "3,4".Split(","));
            Assert.Equal("1,2,3,4", test.ToString());

            QQConnectScopes.TryAdd(test.Scope, "2,3,5,6".Split(","));
            Assert.Equal("1,2,3,4,5,6", test.ToString());
        }


        [Theory]
        [InlineData("1", "1")]
        [InlineData("1,2", "1", "2")]
        [InlineData("1,2,3", "1", "2", "3")]
        [InlineData("1,2,3", "1", "1", "2", "3")]
        public void Scope_TryAdd_Test(string expected, string origin, params string[] values)
        {
            var test = new ScopeTester();

            test.Scope.Add(origin);
            Debug.WriteLine(test.ToString());

            QQConnectScopes.TryAdd(test.Scope, values);
            Debug.WriteLine(test.ToString());

            Assert.Equal(expected, test.ToString());
        }

        [Theory]
        [InlineData("get_user_info", QQConnectScopes.get_user_info)]
        [InlineData("get_user_info,list_album", QQConnectScopes.get_user_info, QQConnectScopes.list_album)]
        [InlineData("get_user_info,list_album,upload_pic", QQConnectScopes.get_user_info, QQConnectScopes.list_album, QQConnectScopes.upload_pic)]
        [InlineData("get_user_info,list_album,upload_pic,do_like", QQConnectScopes.get_user_info, QQConnectScopes.list_album, QQConnectScopes.upload_pic, QQConnectScopes.do_like)]
        [InlineData("get_user_info,list_album,upload_pic,do_like", QQConnectScopes.get_user_info, QQConnectScopes.get_user_info, QQConnectScopes.list_album, QQConnectScopes.upload_pic, QQConnectScopes.do_like)]
        public void Scope_TryAdd_RealValues_Test(string expected, string origin, params string[] values)
        {
            var test = new ScopeTester();

            test.Scope.Add(origin.ToString());
            Debug.WriteLine(test.ToString());

            QQConnectScopes.TryAdd(test.Scope, values);
            Debug.WriteLine(test.ToString());

            Assert.Equal(expected, test.ToString());
        }
    }
}
