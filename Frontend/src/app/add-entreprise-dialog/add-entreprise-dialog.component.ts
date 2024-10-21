// src/app/add-entreprise-dialog/add-entreprise-dialog.component.ts
import { Component } from '@angular/core';
import { MatDialogRef } from '@angular/material/dialog';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { EntrepriseService } from 'src/app/services/entreprise.service';

@Component({
  selector: 'app-add-entreprise-dialog',
  templateUrl: './add-entreprise-dialog.component.html',
  styleUrls: ['./add-entreprise-dialog.component.scss']
})
export class AddEntrepriseDialogComponent {
  addForm: FormGroup;

  constructor(
    private fb: FormBuilder,
    private entrepriseService: EntrepriseService,
    private dialogRef: MatDialogRef<AddEntrepriseDialogComponent>
  ) {
    this.addForm = this.fb.group({
      name: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      phone: ['', Validators.required]
    });
  }

  onSubmit(): void {
    if (this.addForm.valid) {
      this.entrepriseService.addEntreprise(this.addForm.value).subscribe(() => {
        this.dialogRef.close(true);
      });
    }
  }

  onCancel(): void {
    this.dialogRef.close();
  }
}
