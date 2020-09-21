using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Kiralama.Data;
using Kiralama.Models;

namespace Kiralama.Controllers
{
    [Authorize(Roles ="Admin")]
    public class YetkilerController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;

     public YetkilerController(ApplicationDbContext context, UserManager<IdentityUser> _userManager, RoleManager<IdentityRole> _roleManager, SignInManager<IdentityUser> _signInManager)
        {

            _context = context;
            userManager = _userManager;
            roleManager = _roleManager;


        }


        public IActionResult Index()
        {
            return View(roleManager.Roles);
        }
        public IActionResult Create()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Create(string name)
        {
            if (ModelState.IsValid)
            {
                var result = await roleManager.CreateAsync(new IdentityRole(name));
                if (result.Succeeded)
                {
                    return RedirectToAction("Index");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
            }

            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Delete(string id)
        {
            var role = await roleManager.FindByIdAsync(id);
            if (role != null)
            {
                var result = await roleManager.DeleteAsync(role);
                if (result.Succeeded)
                {
                    TempData["message"] = $"{role.Name} silindi.";
                    return RedirectToAction("Index");
                }
                else
                {
                    foreach (var item in result.Errors)
                    {
                        ModelState.AddModelError("", item.Description);
                    }

                }
            }

            return RedirectToAction("Index");



        }
        public async Task<IActionResult> Edit(string id)
        {
            IdentityRole role = await roleManager.FindByIdAsync(id);
            var members = new List<IdentityUser>();
            var notMembers = new List<IdentityUser>();
            foreach (var user in userManager.Users)
            {
                var list = await userManager.IsInRoleAsync(user, role.Name)
                    ? members : notMembers;

                list.Add(user);
            }
            var model = new RoleDetails()
            {
                Role = role,
                Members = members,
                NotMembers = notMembers
            };
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> Edit(RoleEditModel model)
        {
            IdentityResult result;

            if (ModelState.IsValid)
            {
                foreach (var userId in model.UsersToAdd ?? new string[] { })
                {
                    var user = await userManager.FindByIdAsync(userId);

                    if (user != null)
                    {
                        result = await userManager.AddToRoleAsync(user, model.RoleName);

                        if (!result.Succeeded)
                        {
                            foreach (var error in result.Errors)
                            {
                                ModelState.AddModelError("", error.Description);
                            }
                        }
                    }
                }

                foreach (var userId in model.UsersToDelete ?? new string[] { })
                {
                    var user = await userManager.FindByIdAsync(userId);

                    if (user != null)
                    {
                        result = await userManager.RemoveFromRoleAsync(user, model.RoleName);

                        if (!result.Succeeded)
                        {
                            foreach (var error in result.Errors)
                            {
                                ModelState.AddModelError("", error.Description);
                            }
                        }
                    }
                }

            }

            if (ModelState.IsValid)
            {
                return RedirectToAction("Index");
            }
            else
            {
                return RedirectToAction("Edit", model.RoleId);
            }


        }
        }
    }


      

