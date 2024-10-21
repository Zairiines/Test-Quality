import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { BlankComponent } from './layouts/blank/blank.component';
import { FullComponent } from './layouts/full/full.component';
import { TableUserComponent } from './tableuser/tableuser.component';
import { TableEntrepriseComponent } from './table-entreprise/table-entreprise.component';
import { TableContratComponent } from './table-contrat/table-contrat.component';
import { DocumentManagerComponent } from './document-manager/document-manager.component';
import { NotificationComponent } from './notification/notification.component';  // Import du NotificationComponent

const routes: Routes = [
  {
    path: '',
    component: FullComponent,
    children: [
      {
        path: '',
        redirectTo: '/dashboard',
        pathMatch: 'full',
      },
      {
        path: 'dashboard',
        loadChildren: () =>
          import('./pages/pages.module').then(m => m.PagesModule),
      },
      {
        path: 'ui-components',
        loadChildren: () =>
          import('./pages/ui-components/ui-components.module').then(
            m => m.UicomponentsModule
          ),
      },
      {
        path: 'extra',
        loadChildren: () =>
          import('./pages/extra/extra.module').then(m => m.ExtraModule),
      },
      {
        path: 'users',
        component: TableUserComponent,
      },
      {
        path: 'entreprises',
        component: TableEntrepriseComponent,
      },
      {
        path: 'contrats',
        component: TableContratComponent,
      },
      {
        path: 'documents',
        component: DocumentManagerComponent,
      },
      {
        path: 'documents/:contractId',
        component: DocumentManagerComponent,
      },
      {
        path: 'notifications',  // Ajout de la route pour NotificationComponent
        component: NotificationComponent,
      },
    ]
  },
  {
    path: '',
    component: BlankComponent,
    children: [
      {
        path: 'authentication',
        loadChildren: () =>
          import('./pages/authentication/authentication.module').then(
            m => m.AuthenticationModule
          ),
      },
    ],
  },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
