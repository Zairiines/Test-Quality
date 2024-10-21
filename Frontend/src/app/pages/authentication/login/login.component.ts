import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../../services/auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
})
export class AppSideLoginComponent {
  loginForm: FormGroup;
  errorMessage: string | null = null;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.loginForm = this.fb.group({
      username: ['', Validators.required],
      password: ['', Validators.required],
      rememberMe: [false],
    });
  }

  onSubmit(): void {
    if (this.loginForm.valid) {
      const { username, password } = this.loginForm.value;
      this.authService.login(username, password).subscribe(
        (response: any) => {
          // Enregistrer le token et les informations de l'utilisateur dans le localStorage en utilisant AuthService
          this.authService.setSession(response); // Utiliser setSession pour stocker le token et l'utilisateur
          // Rediriger vers le tableau de bord
          this.router.navigate(['/dashboard']);
        },
        (error: any) => {
          // Afficher un message d'erreur
          this.errorMessage = error.message || 'Une erreur est survenue lors de la connexion.';
          console.error('Login error', error);
        }
      );
    }
  }
}
