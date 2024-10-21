import { Component, Inject } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Entreprise } from '../models/entreprise.model'; // Modifiez le chemin selon votre projet

@Component({
  selector: 'app-update-entreprise-dialog',
  templateUrl: './update-entreprise-dialog.component.html',
  styleUrls: ['./update-entreprise-dialog.component.scss']
})
export class UpdateEntrepriseDialogComponent {
  updateForm: FormGroup;

  constructor(
    public dialogRef: MatDialogRef<UpdateEntrepriseDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { entreprise: Entreprise },
    private fb: FormBuilder
  ) {
    // Initialisation du formulaire avec les données de l'entreprise
    this.updateForm = this.fb.group({
      name: [data.entreprise?.name || '', Validators.required],
      email: [data.entreprise?.email || '', [Validators.required, Validators.email]],
      phone: [data.entreprise?.phone || '', Validators.required]
    });
  }

  // Méthode pour soumettre les modifications
  onUpdate(): void {
    if (this.updateForm.valid) {
      this.dialogRef.close(this.updateForm.value);
    }
  }

  // Méthode pour annuler la modification
  onCancel(): void {
    this.dialogRef.close();
  }
}
