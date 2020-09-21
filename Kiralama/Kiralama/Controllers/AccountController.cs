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
    
    [Authorize]
    public class AccountController : Controller
    {
        private IPasswordValidator<IdentityUser> passwordValidator;
        private IPasswordHasher<IdentityUser> passwordHasher;
        private UserManager<IdentityUser> userManager;
        private SignInManager<IdentityUser> signinManager;
        private readonly ApplicationDbContext context;

        public AccountController(ApplicationDbContext _context,UserManager<IdentityUser> _userManager, SignInManager<IdentityUser> _signinManager, IPasswordValidator<IdentityUser> passValidator, IPasswordHasher<IdentityUser> passHasher)
        {
            userManager = _userManager;
            signinManager = _signinManager;
            passwordValidator = passValidator;
            passwordHasher = passHasher;
            context = _context;
        }

        [AllowAnonymous]
        public IActionResult Login()
        {
            
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByNameAsync(model.UserName);

                if (user != null)
                {
                    await signinManager.SignOutAsync();
                    var result = await signinManager.PasswordSignInAsync(user, model.Password, false, false);
                    if (result.Succeeded)
                    {
                        return RedirectToAction("Index","Home");
                    }
                }
                ModelState.AddModelError("Login", "Yanlış kullanıcı adı ya da şifre.");
            }
            
            return View("Login", model);
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterModel model, string isTrainer)
        {
            
            
         
            if (ModelState.IsValid)
            {
                IdentityUser user = GetUser();
                user.UserName = model.UserName;
                user.Email = model.Email;
                var pW = model.Password;
                var result = await userManager.CreateAsync(user, model.Password);


                if (result.Succeeded)
                {
                    var user2 = await userManager.FindByNameAsync(model.UserName);

                    await userManager.AddToRoleAsync(user2, "User");
                    
                    if (user != null)
                    {
                        await signinManager.SignOutAsync();
                        var result2 = await signinManager.PasswordSignInAsync(user, pW, false, false);

                    }

                    return RedirectToAction("Index", "Home");
                }
                else
                {
                   
                    var errorHandling=result.Errors.ToList();
                    foreach (var error in errorHandling)
                    {
                        if(error.Code== "DuplicateUserName")
                        {
                            ModelState.AddModelError("Register", "Bu kullanıcı zaten kayıtlı.");
                        }
                        if(error.Code=="PasswordRequiresUpper")
                        {
                            ModelState.AddModelError("Register", "Şifrede büyük harf bulunmalıdır.");
                        }
                        if (error.Code== "PasswordRequiresNonAlphanumeric")
                        {
                            ModelState.AddModelError("Register", "Şifrede işaret bulunmalıdır.");
                        }
                        if(error.Code== "PasswordRequiresDigit")
                        {
                            ModelState.AddModelError("Register", "Şifrede sayı bulunmalıdır.");
                        }
                    }

                   

                }

            }
            return View("Register", model);

        }

        private static IdentityUser GetUser()
        {
            return new IdentityUser();
        }

        [Authorize(Roles ="Admin")]
        public IActionResult Index()
        {
            return View(userManager.Users);
        }
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await signinManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Delete(string Id)
        {
            var user = await userManager.FindByIdAsync(Id);

            if (user != null)
            {
                var result = await userManager.DeleteAsync(user);

                if (result.Succeeded)
                {
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
            else
            {
                ModelState.AddModelError("", "Kullanıcı Bulunamadı");
            }
            return View("Index", userManager.Users);
        }


        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Update()
        {
             
            if (userManager.GetUserId(HttpContext.User) != null)
            {
                var userN = userManager.GetUserId(HttpContext.User);
                Guid userGuid = Guid.Parse(userN);
                string abc = userManager.GetUserId(User);
               

                var user = await userManager.FindByIdAsync(abc);
                user.UserName = userManager.GetUserName(User);
                
                
                if (user != null)
                {
                    return View(user);
                }
            }
           
            else
            {
                return RedirectToAction("Index","Home");
            }
            return RedirectToAction("Index","Home");
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> Update(string Password)
        {
                           
                    var userN = userManager.GetUserId(HttpContext.User);
                    Guid userGuid = Guid.Parse(userN);
                    string abc = userManager.GetUserId(User);
                     var user = await userManager.FindByIdAsync(abc);
                    string userName = userManager.GetUserName(User);
                     var email = user.Email;



            user.Email = email.ToString();
            user.UserName = userName;
            
                IdentityResult validPass = null;

                if (!string.IsNullOrEmpty(Password))
                {
                    validPass = await passwordValidator.ValidateAsync(userManager, user, Password);

                    if (validPass.Succeeded)
                    {
                        user.PasswordHash = passwordHasher.HashPassword(user, Password);
                    }
                    else
                    {
                        foreach (var item in validPass.Errors)
                        {
                            ModelState.AddModelError("", item.Description);
                        }
                    }
                }

                if (validPass.Succeeded)
                {
                    var result = await userManager.UpdateAsync(user);
                    
                    if (result.Succeeded)
                    {
                        return RedirectToAction("Index","Home");
                    }
                    else
                    {
                        foreach (var item in result.Errors)
                        {
                            ModelState.AddModelError("", item.Description);
                        }
                    }
                }

            return View(user);
        }
        public async Task<IActionResult> Details()
        {
            var userN = userManager.GetUserId(HttpContext.User);
            Guid userGuid = Guid.Parse(userN);
            string abc = userManager.GetUserId(User);
            string userName = userManager.GetUserName(User);
            var user = await userManager.FindByIdAsync(abc);
            user.UserName = userName;

            return RedirectToAction("Update","Account");
        }

        public async Task<IActionResult> Filmlerim()
        {
            if (userManager.GetUserId(HttpContext.User) != null)
            {
                var UserN = userManager.GetUserId(HttpContext.User);
                Guid userGuid = Guid.Parse(UserN);

                List<SatinAlma> purchaseIdList = context.SatinAlma.Where(q => q.UserID == userGuid).ToList();
                List<Filmler> filmler = new List<Filmler>();
                foreach (var item in purchaseIdList)
                {

                    filmler.Add(context.Filmler.Where(q => q.Id == item.FilmID).FirstOrDefault());

                }

                return View(filmler);
            }

            return RedirectToAction("Index");
        }
    


    [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }



    }
}