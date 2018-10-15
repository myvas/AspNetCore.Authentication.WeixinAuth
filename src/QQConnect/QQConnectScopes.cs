using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Myvas.AspNetCore.Authentication
{
    public static class QQConnectScopes
    {
        public const string get_user_info = "get_user_info";
        public const string list_album = "list_album";
        public const string upload_pic = "upload_pic";
        public const string do_like = "do_like";

        #region Helpers
        public static ICollection<string> TryAdd(ICollection<string> currentScopes, params string[] scopes)
        {
            Array.ForEach(scopes, x =>
            {
                if (!currentScopes.Contains(x))
                {
                    currentScopes.Add(x);
                }
            });
            return currentScopes;
        }

        //public static ICollection<string> TryAdd(ICollection<string> currentScopes, params QQConnectScopes[] scopes)
        //{
        //    Array.ForEach(scopes, x =>
        //    {
        //        var s = x.ToString();
        //        if (!currentScopes.Contains(s))
        //        {
        //            currentScopes.Add(s);
        //        }
        //    });
        //    return currentScopes;
        //}
        #endregion
    }
}
