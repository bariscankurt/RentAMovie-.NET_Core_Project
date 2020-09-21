using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Kiralama.Models
{
    public class UserRole
    {
        public int Id { get; set; }
        public string RoleName { get; set; }
        public List<string> Users { get; set; }
        public string Email { get; set; }
    }
}
