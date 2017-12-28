using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Demo.Models
{
    public class RegisterVerifyCodeViewModel : ReturnableViewModel
    {
        public string UserId { get; set; }
        public string PhoneNumber { get; set; }

        [Required(ErrorMessage = "验证码不能为空！")]
        public string Code { get; set; }
    }
}
