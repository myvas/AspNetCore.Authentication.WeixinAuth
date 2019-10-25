using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Myvas.AspNetCore.Authentication.WeixinAuth.Internal
{
    internal static class WeixinAuthHandlerHelper
    {
        #region 错误时微信会返回含有两个字段的JSON数据包
        /// <summary>
        ///  errcode
        /// </summary>
        public static int GetErrorCode(JsonDocument payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.RootElement.GetInt32("errcode", 0);
        }

        /// <summary>
        ///  errmsg
        /// </summary>
        public static string GetErrorMessage(JsonDocument payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.RootElement.GetString("errmsg");
        }
        #endregion

        /// <summary>
        ///  openid
        /// </summary>
        public static string GetOpenId(JsonDocument payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.RootElement.GetString("openid");
        }

        /// <summary>
        /// nickname 微信用户昵称。
        /// </summary>
        public static string GetNickName(JsonDocument payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.RootElement.GetString("nickname");
        }

        /// <summary>
        /// headimgurl 微信头像。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetHeadImageUrl(JsonDocument payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.RootElement.GetString("headimgurl");
        }

        /// <summary>
        /// sex 姓别。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetGender(JsonDocument payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.RootElement.GetString("sex");
        }

        /// <summary>
        /// country 国家。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetCountry(JsonDocument payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.RootElement.GetString("country");
        }

        /// <summary>
        /// province 省份。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetProvince(JsonDocument payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.RootElement.GetString("province");
        }

        /// <summary>
        /// city 城市。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetCity(JsonDocument payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.RootElement.GetString("city");
        }

        /// <summary>
        /// unionid 用户统一标识。针对一个微信开放平台帐号下的应用，同一用户的unionid是唯一的。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetUnionId(JsonDocument payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.RootElement.GetString("unionid");
        }

        /// <summary>
        /// privilege 用户特权信息，json数组，如微信沃卡用户为（chinaunicom）。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static IEnumerable<string> GetPrivileges(JsonDocument payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.RootElement.GetStringArray("privilege");
        }
    }
}
