import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router'; // Importer RouterModule pour la navigation
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';

import { TableContratComponent } from './table-contrat.component';
import { AddContractDialogComponent } from '../add-contract-dialog/add-contract-dialog.component';
import { UpdateContractDialogComponent } from '../update-contract-dialog/update-contract-dialog.component';

@NgModule({
  declarations: [
    TableContratComponent,
    AddContractDialogComponent,
    UpdateContractDialogComponent
  ],
  imports: [
    CommonModule,
    RouterModule, // Ajouter RouterModule aux imports si nécessaire
    MatTableModule,
    MatButtonModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    FormsModule,
    ReactiveFormsModule
  ],
  exports: [
    TableContratComponent,
    AddContractDialogComponent, // Expose AddContractDialogComponent si utilisé ailleurs
    UpdateContractDialogComponent // Expose UpdateContractDialogComponent si utilisé ailleurs
  ],
  
})
export class TableContratModule { }
