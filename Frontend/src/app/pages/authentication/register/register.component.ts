import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../../services/auth.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  //styleUrls: ['./register.component.css'] // Assurez-vous que ce fichier existe
})
export class AppSideRegisterComponent {
  registerForm: FormGroup;
  errorMessage: string | null = null;
  roles: string[] = ['ADMIN', 'UTILISATEUR']; // Liste des rôles disponibles

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.registerForm = this.fb.group({
      username: ['', [Validators.required, Validators.minLength(6)]],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8)]], // Validation supplémentaire pour le mot de passe
      role: ['', Validators.required] // Ajout du contrôle pour le rôle
    });
  }

  onSubmit() {
    if (this.registerForm.valid) {
      this.authService.register(this.registerForm.value).subscribe(
        (response: any) => {
          // Affichage d'un message de succès ou gestion supplémentaire
          this.router.navigate(['/dashboard']);
        },
        (error: any) => {
          // Gestion des erreurs détaillées
          if (error.status === 0) {
            this.errorMessage = 'Impossible de se connecter au serveur. Veuillez vérifier que le backend est en cours d\'exécution.';
          } else {
            this.errorMessage = error.error?.message || 'Une erreur inconnue est survenue. Veuillez réessayer.';
          }
          console.error('Registration error', error);
        }
      );
    } else {
      // Affichage d'un message d'erreur si le formulaire n'est pas valide
      this.errorMessage = 'Veuillez remplir tous les champs correctement.';
    }
  }
}