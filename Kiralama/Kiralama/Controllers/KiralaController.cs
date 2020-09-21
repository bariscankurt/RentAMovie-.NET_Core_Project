using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Kiralama.Data;
using Kiralama.Models;
using Microsoft.AspNetCore.Authorization;

namespace Kiralama.Controllers
{
    [Authorize(Roles = "Admin")]
    public class KiralaController : Controller
    {
        private readonly ApplicationDbContext _context;

        public KiralaController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: SatinAlma
      
        public async Task<IActionResult> Index()
        {
            return View(await _context.SatinAlma.ToListAsync());
        }

        
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var satinAlma = await _context.SatinAlma
                .FirstOrDefaultAsync(m => m.Id == id);
            if (satinAlma == null)
            {
                return NotFound();
            }

            return View(satinAlma);
        }

        // GET: SatinAlma/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: SatinAlma/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,UserID,FilmID")] SatinAlma satinAlma)
        {
            if (ModelState.IsValid)
            {
                _context.Add(satinAlma);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(satinAlma);
        }

        // GET: SatinAlma/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var satinAlma = await _context.SatinAlma.FindAsync(id);
            if (satinAlma == null)
            {
                return NotFound();
            }
            return View(satinAlma);
        }

        // POST: SatinAlma/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,UserID,FilmID")] SatinAlma satinAlma)
        {
            if (id != satinAlma.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(satinAlma);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!SatinAlmaExists(satinAlma.Id))
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
            return View(satinAlma);
        }

        // GET: SatinAlma/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var satinAlma = await _context.SatinAlma
                .FirstOrDefaultAsync(m => m.Id == id);
            if (satinAlma == null)
            {
                return NotFound();
            }

            return View(satinAlma);
        }

        // POST: SatinAlma/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var satinAlma = await _context.SatinAlma.FindAsync(id);
            _context.SatinAlma.Remove(satinAlma);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool SatinAlmaExists(int id)
        {
            return _context.SatinAlma.Any(e => e.Id == id);
        }
    }
}
