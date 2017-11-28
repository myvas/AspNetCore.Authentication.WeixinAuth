using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth.Demo.Models.AccountViewModels
{
    public class LoginViewModel
    {
        [Required]
        [ChineseMobile]
        public string PhoneNumber { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
