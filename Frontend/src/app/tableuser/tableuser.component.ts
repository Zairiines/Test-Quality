import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatDialog } from '@angular/material/dialog';
import { UserService } from '../services/user.service';
import { User } from '../models/user.model';
import { AddUserDialogComponent } from '../add-user-dialog/add-user-dialog.component';

@Component({
  selector: 'app-tableuser',
  templateUrl: './tableuser.component.html',
  styleUrls: ['./tableuser.component.scss']
})
export class TableUserComponent implements OnInit {
  tableData: User[] = [];
  showConfirmation = false;
  editingUserId: number | null = null;
  updateForm: FormGroup;
  errorMessage: string | null = null;

  displayedColumns: string[] = ['username', 'email', 'actions'];

  constructor(
    private userService: UserService,
    private fb: FormBuilder,
    private dialog: MatDialog // Injecter MatDialog
  ) {
    this.updateForm = this.fb.group({
      username: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      password: ['', Validators.required]
    });
  }

  ngOnInit(): void {
    this.fetchUsers();
  }

  fetchUsers(): void {
    this.userService.getUsers().subscribe(
      (response) => {
        this.tableData = response;
      },
      (error) => {
        console.error('Error fetching users:', error);
        this.errorMessage = 'Unable to fetch users. Please try again later.';
      }
    );
  }

  openAddUserDialog(): void {
    const dialogRef = this.dialog.open(AddUserDialogComponent);

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.fetchUsers(); // Rafraîchir la liste des utilisateurs après l'ajout
      }
    });
  }

  selectUserForUpdate(user: User): void {
    this.editingUserId = user.id;
    this.updateForm.patchValue({
      username: user.username,
      email: user.email,
      password: ''
    });
    this.errorMessage = null;
  }

  openConfirmation(id: number): void {
    this.showConfirmation = true;
    this.editingUserId = id;
    this.errorMessage = null;
  }

  confirmDelete(): void {
    if (this.editingUserId !== null) {
      this.userService.deleteUser(this.editingUserId).subscribe(
        () => {
          this.fetchUsers(); // Rafraîchir la liste des utilisateurs
          this.resetState();
        },
        (error) => {
          this.errorMessage = error.message || 'Unable to delete user. Please try again later.';
          console.error('Error deleting user:', error);
        }
      );
    }
  }

  cancelDelete(): void {
    this.showConfirmation = false;
    this.errorMessage = null;
  }

  updateUser(): void {
    if (this.editingUserId !== null) {
      const updatedUser: Partial<User> = this.updateForm.value;
      this.userService.updateUser(this.editingUserId, updatedUser).subscribe(
        () => {
          this.fetchUsers(); // Rafraîchir la liste des utilisateurs
          this.resetState();
        },
        (error) => {
          this.errorMessage = error.message || 'Impossible de mettre à jour l\'utilisateur. Veuillez réessayer plus tard.';
          console.error('Error updating user:', error);
        }
      );
    }
  }

  cancelEdit(): void {
    this.resetState();
  }

  private resetState(): void {
    this.editingUserId = null;
    this.updateForm.reset();
    this.errorMessage = null;
    this.showConfirmation = false;
  }
}
