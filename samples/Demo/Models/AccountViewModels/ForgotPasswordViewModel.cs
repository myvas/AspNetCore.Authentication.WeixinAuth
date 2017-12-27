using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Demo.Models
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [ChineseMobile]
        public string PhoneNumber { get; set; }
    }
}
