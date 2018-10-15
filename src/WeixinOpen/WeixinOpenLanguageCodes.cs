using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace Myvas.AspNetCore.Authentication
{
    public enum WeixinOpenLanguageCodes
    {
        [Display(ShortName = "zh_CN", Name = "简体")]
        zh_CN,

        [Display(ShortName = "zh_TW", Name = "繁体")]
        zh_TW,

        [Display(ShortName = "en", Name = "英语")]
        en
    }

}
