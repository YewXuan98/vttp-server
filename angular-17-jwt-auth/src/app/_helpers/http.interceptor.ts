import { Injectable } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest, HTTP_INTERCEPTORS, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, switchMap } from 'rxjs/operators';

import { StorageService } from '../_services/storage.service';
import { EventBusService } from '../_shared/event-bus.service';
import { EventData } from '../_shared/event.class';
import { AuthService } from '../_services/auth.service';

@Injectable()
export class HttpRequestInterceptor implements HttpInterceptor {
  private isRefreshing = false;

  constructor(
    private storageService: StorageService,
    private authService: AuthService,
    private eventBusService: EventBusService
  ) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
     // Retrieve the JWT token from the storage service
    const authToken = this.storageService.getToken();
    // req = req.clone({
    //   withCredentials: true,
    // });
    // Clone the request to add the new header.
    const authReq = authToken ? req.clone({
      setHeaders: { Authorization: `Bearer ${authToken}` }
    }) : req;

    if (!req.url.includes('auth/signin') && !req.url.includes('auth/refreshtoken')) {
      if (this.storageService.isLoggedIn() && this.storageService.isTokenExpired()) {
          return this.handle401Error(req, next);
      }
  }

    return next.handle(authReq).pipe(
      catchError((error) => {
        if (
          error instanceof HttpErrorResponse &&
          !req.url.includes('auth/signin') &&
          error.status === 401
        ) {
          return this.handle401Error(req, next);
        }

        return throwError(() => error);
      })
    );
  }

  private handle401Error(request: HttpRequest<any>, next: HttpHandler) {
    if (!this.isRefreshing) {
      this.isRefreshing = true;
  
      if (this.storageService.isLoggedIn()) {
        return this.authService.refreshToken().pipe(
          switchMap(() => {
            this.isRefreshing = false;
            return next.handle(request);
          }),
          catchError((error) => {
            this.isRefreshing = false;
  
            if (error.status === 401 || error.status === 403) { // Correct status checks
              this.eventBusService.emit(new EventData('logout', null));
            }
  
            return throwError(() => error);
          })
        );
      }
    }

    
  
    return next.handle(request);
  }
}  

//   private handle401Error(request: HttpRequest<any>, next: HttpHandler) {
//     if (!this.isRefreshing) {
//       this.isRefreshing = true;

//       if (this.storageService.isLoggedIn()) {
//         return this.authService.refreshToken().pipe(
//           switchMap(() => {
//             this.isRefreshing = false;

//             return next.handle(request);
//           }),
//           catchError((error) => {
//             this.isRefreshing = false;

//             if (error.status == '403' || '401') {
//               this.eventBusService.emit(new EventData('logout', null));
//             }

//             return throwError(() => error);
//           })
//         );
//       }
//     }

//     return next.handle(request);
//   }
// }

export const httpInterceptorProviders = [
  { provide: HTTP_INTERCEPTORS, useClass: HttpRequestInterceptor, multi: true },
];
