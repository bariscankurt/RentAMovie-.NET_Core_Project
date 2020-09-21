using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Kiralama.Models;

namespace Kiralama.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
       
        public DbSet<Kiralama.Models.Filmler> Filmler { get; set; }
        public DbSet<Kiralama.Models.SatinAlma> SatinAlma { get; set; }


    }


}
