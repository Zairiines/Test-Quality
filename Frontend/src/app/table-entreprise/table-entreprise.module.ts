import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormsModule } from '@angular/forms'; // Ajoutez FormsModule ici

// Import Material Modules
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule } from '@angular/material/dialog';
import { MatTableModule } from '@angular/material/table';
import { MatIconModule } from '@angular/material/icon';

import { TableEntrepriseComponent } from './table-entreprise.component';
import { AddEntrepriseDialogComponent } from '../add-entreprise-dialog/add-entreprise-dialog.component';
import { UpdateEntrepriseDialogComponent } from '../update-entreprise-dialog/update-entreprise-dialog.component';
import { EntrepriseService } from 'src/app/services/entreprise.service';
import { UserService } from 'src/app/services/user.service';

@NgModule({
  declarations: [
    TableEntrepriseComponent,
    AddEntrepriseDialogComponent,
    UpdateEntrepriseDialogComponent
  ],
  imports: [
    CommonModule,
    ReactiveFormsModule,
    FormsModule, // Ajoutez FormsModule ici
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatDialogModule,
    MatTableModule,
    MatIconModule
  ],
  providers: [
    EntrepriseService,
    UserService
  ],
  exports: [
    TableEntrepriseComponent
  ]
})
export class TableEntrepriseModule { }
