using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WeixinAuth.Demo.Models
{
    public class BindPhoneViewModel : ReturnableViewModel
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string PhoneNumber { get; set; }
    }
}
