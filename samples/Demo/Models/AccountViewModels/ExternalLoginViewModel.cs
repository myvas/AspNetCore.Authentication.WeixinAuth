using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Demo.Models
{
    public class ExternalLoginPhoneNumberViewModel : ReturnableViewModel
    {
        [Required]
        [ChineseMobile]
        public string PhoneNumber { get; set; }

        public string LoginProvider { get; set; }
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
