using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Kiralama.Models
{
    public class SatinAlma
    {
        public int Id { get; set; }
        public Guid UserID { get; set; }
        public int FilmID { get; set; }
    }
}
