using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Kiralama.Data;
using Kiralama.Models;

namespace Kiralama.Controllers
{
    public class FilmlerController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;

        public FilmlerController(ApplicationDbContext context, UserManager<IdentityUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        // GET: Filmler
        public async Task<IActionResult> Index()
        {
            if (User.IsInRole("Admin"))
            {
                return View("AdminIndex",await _context.Filmler.ToListAsync());
            }
            else
            {
                return View("Index",await _context.Filmler.ToListAsync());
            }
            
        }

        // GET: Filmler/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var filmler = await _context.Filmler
                .FirstOrDefaultAsync(m => m.Id == id);
            if (filmler == null)
            {
                return NotFound();
            }

            return View(filmler);
        }

        [Authorize(Roles = "Admin")]
        public IActionResult Create()
        {
            return View();
        }

        // POST: Filmler/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,FilmAdi,ResimYolu,Tur,Dil,Sure,Aciklama,Yonetmen,Oyuncular,KiralamaUcreti")] Filmler filmler)
        {
            if (ModelState.IsValid)
            {
                _context.Add(filmler);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(filmler);
        }

        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var filmler = await _context.Filmler.FindAsync(id);
            if (filmler == null)
            {
                return NotFound();
            }
            return View(filmler);
        }

        // POST: Filmler/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,FilmAdi,ResimYolu,Tur,Dil,Sure,Aciklama,Yonetmen,Oyuncular,KiralamaUcreti")] Filmler filmler)
        {
            if (id != filmler.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(filmler);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!FilmlerExists(filmler.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(filmler);
        }

        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var filmler = await _context.Filmler
                .FirstOrDefaultAsync(m => m.Id == id);
            if (filmler == null)
            {
                return NotFound();
            }

            return View(filmler);
        }

        // POST: Filmler/Delete/5
        [Authorize(Roles = "Admin")]
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var filmler = await _context.Filmler.FindAsync(id);
            _context.Filmler.Remove(filmler);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool FilmlerExists(int id)
        {
            return _context.Filmler.Any(e => e.Id == id);
        }
        [Authorize]
        public async Task<IActionResult> Kirala(int? id)
        {
            Filmler film = _context.Filmler.Find(id);
            SatinAlma sta = new SatinAlma();
            if (_userManager.GetUserId(HttpContext.User) != null)
            {
                var userN = _userManager.GetUserId(HttpContext.User);
                Guid userGuid = Guid.Parse(userN);
                sta.FilmID = film.Id;
                sta.UserID = userGuid;

                bool asd = false;
                var purchaseIdList = _context.SatinAlma.Where(q => q.UserID == userGuid).Select(q => q.FilmID).ToList();
                foreach (var item in purchaseIdList)
                {
                    asd = purchaseIdList.Contains(film.Id);
                }

                if (asd == false)
                {
                    _context.Add(sta);
                    await _context.SaveChangesAsync();
                    RedirectToAction("Index");
                }
                else
                {
                    RedirectToAction("Error", "Home");
                }
            }

            return RedirectToAction("Index");
        }
    }
}