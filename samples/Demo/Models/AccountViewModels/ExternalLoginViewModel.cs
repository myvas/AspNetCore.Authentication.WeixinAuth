using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth.Demo.Models.AccountViewModels
{
    public class ExternalLoginPhoneNumberViewModel
    {
        [Required]
        [ChineseMobile]
        public string PhoneNumber { get; set; }
    }

    public class ExternalLoginVcodeViewModel
    {
        [Required]
        [ChineseMobile]
        public string PhoneNumber { get; set; }

        [Required]
        public string Code { get; set; }
    }
}
