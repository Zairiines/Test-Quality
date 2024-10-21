import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatIconModule } from '@angular/material/icon'; // Importer MatIconModule
import { MatTableModule } from '@angular/material/table'; // Importer MatTableModule
import { RouterModule } from '@angular/router'; // Importer RouterModule si nécessaire

import { DocumentManagerComponent } from './document-manager.component';
import { DocumentService } from '../services/document.service';
import { UploadDocumentDialogComponent } from '../upload-document-dialog/upload-document-dialog.component';

@NgModule({
  declarations: [
    DocumentManagerComponent,
    UploadDocumentDialogComponent
  ],
  imports: [
    CommonModule,
    FormsModule,
    HttpClientModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatIconModule, // Ajouter MatIconModule aux imports
    MatTableModule, // Ajouter MatTableModule aux imports
    RouterModule // Ajouter RouterModule aux imports si nécessaire
  ],
  providers: [DocumentService],
  exports: [
    DocumentManagerComponent
  ],
})
export class DocumentManagerModule { }
