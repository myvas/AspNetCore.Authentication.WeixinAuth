using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth.Demo.Models.AccountViewModels
{
    public class ExternalLoginViewModel
    {
        [Required]
        [ChineseMobile]
        public string PhoneNumber { get; set; }
    }
}
