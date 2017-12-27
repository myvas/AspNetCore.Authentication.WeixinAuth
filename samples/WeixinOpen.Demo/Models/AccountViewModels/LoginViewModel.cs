using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WeixinOpen.Demo.Models
{
    public class LoginViewModel : ReturnableViewModel
    {
        [Required]
        public string PhoneNumberOrEmailOrUserName { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
