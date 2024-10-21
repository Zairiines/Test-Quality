import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule } from '@angular/forms'; 
import { MatDialogModule } from '@angular/material/dialog'; // Importer MatDialogModule
import { MatTableModule } from '@angular/material/table'; // Importer MatTableModule
import { MatFormFieldModule } from '@angular/material/form-field'; // Importer MatFormFieldModule
import { MatInputModule } from '@angular/material/input'; // Importer MatInputModule
import { MatButtonModule } from '@angular/material/button'; // Importer MatButtonModule
import { TableUserComponent } from './tableuser.component';
import { AddUserDialogComponent } from '../add-user-dialog/add-user-dialog.component'; // Importer AddUserDialogComponent

@NgModule({
  declarations: [
    TableUserComponent,
    AddUserDialogComponent // Déclarer AddUserDialogComponent ici
  ],
  imports: [
    CommonModule,
    ReactiveFormsModule, 
    MatDialogModule, // Ajouter MatDialogModule ici
    MatTableModule, // Ajouter MatTableModule ici
    MatFormFieldModule, // Ajouter MatFormFieldModule ici
    MatInputModule, // Ajouter MatInputModule ici
    MatButtonModule // Ajouter MatButtonModule ici
  ],
  exports: [
    TableUserComponent
  ],
})
export class TableUserModule {}
