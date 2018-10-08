using AspNetCore.Authentication.QQ;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Xunit;

namespace UnitTests
{
    public class QQOAuthScopesTests
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

            QQOAuthScopes.TryAdd(test.Scope, "2".Split(","));
            Assert.Equal("1,2", test.ToString());

            QQOAuthScopes.TryAdd(test.Scope, "3,4".Split(","));
            Assert.Equal("1,2,3,4", test.ToString());

            QQOAuthScopes.TryAdd(test.Scope, "2,3,5,6".Split(","));
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

            QQOAuthScopes.TryAdd(test.Scope, values);
            Debug.WriteLine(test.ToString());

            Assert.Equal(expected, test.ToString());
        }

        [Theory]
        [InlineData("get_user_info", QQOAuthScopes.Items.get_user_info)]
        [InlineData("get_user_info,list_album", QQOAuthScopes.Items.get_user_info, QQOAuthScopes.Items.list_album)]
        [InlineData("get_user_info,list_album,upload_pic", QQOAuthScopes.Items.get_user_info, QQOAuthScopes.Items.list_album, QQOAuthScopes.Items.upload_pic)]
        [InlineData("get_user_info,list_album,upload_pic,do_like", QQOAuthScopes.Items.get_user_info, QQOAuthScopes.Items.list_album, QQOAuthScopes.Items.upload_pic, QQOAuthScopes.Items.do_like)]
        [InlineData("get_user_info,list_album,upload_pic,do_like", QQOAuthScopes.Items.get_user_info, QQOAuthScopes.Items.get_user_info, QQOAuthScopes.Items.list_album, QQOAuthScopes.Items.upload_pic, QQOAuthScopes.Items.do_like)]
        public void Scope_TryAdd_Enum_Test(string expected, QQOAuthScopes.Items origin, params QQOAuthScopes.Items[] values)
        {
            var test = new ScopeTester();

            test.Scope.Add(origin.ToString());
            Debug.WriteLine(test.ToString());

            QQOAuthScopes.TryAdd(test.Scope, values);
            Debug.WriteLine(test.ToString());

            Assert.Equal(expected, test.ToString());
        }
    }
}
