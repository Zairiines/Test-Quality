import { Component, Inject } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { UserService } from '../services/user.service';

@Component({
  selector: 'app-add-user-dialog',
  templateUrl: './add-user-dialog.component.html',
  styleUrls: ['./add-user-dialog.component.scss']
})
export class AddUserDialogComponent {
  addUserForm: FormGroup;

  constructor(
    public dialogRef: MatDialogRef<AddUserDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: any,
    private fb: FormBuilder,
    private userService: UserService
  ) {
    this.addUserForm = this.fb.group({
      username: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      password: ['', Validators.required]
    });
  }

  onAddUser(): void {
    if (this.addUserForm.valid) {
      const newUser = this.addUserForm.value;
      this.userService.addUser(newUser).subscribe(
        (response) => {
          this.dialogRef.close(true); // Fermer le dialogue et indiquer un succès
        },
        (error) => {
          console.error('Error adding user:', error);
          // Gérer les erreurs d'ajout ici
        }
      );
    }
  }

  onCancel(): void {
    this.dialogRef.close(); // Fermer le dialogue sans ajout
  }
}
