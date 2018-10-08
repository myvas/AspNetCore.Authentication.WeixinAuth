using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Demo.Models
{
    public class IndexViewModel
    {
        public string Username { get; set; }

        public bool IsPhoneNumberConfirmed { get; set; }

        [Required]
        [ChineseMobile]
        public string PhoneNumber { get; set; }
        
        public string StatusMessage { get; set; }
    }
}
