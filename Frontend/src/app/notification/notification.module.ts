import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';

import { NotificationComponent } from './notification.component';
import { NotificationService } from '../services/notification.service';

@NgModule({
  declarations: [
    NotificationComponent
  ],
  imports: [
    CommonModule,
    HttpClientModule // Importation d'HttpClientModule
  ],
  providers: [NotificationService],
  exports: [NotificationComponent] // Exporter le composant si vous souhaitez l'utiliser dans d'autres modules
})
export class NotificationModule { }
