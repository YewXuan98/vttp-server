import { Injectable } from '@angular/core';
import {jwtDecode} from "jwt-decode";

const USER_KEY = 'auth-user';
const TOKEN_KEY = 'auth-token'

@Injectable({
  providedIn: 'root'
})
export class StorageService {
  constructor() {}

  clean(): void {
    window.sessionStorage.clear();
  }

  public saveUser(user: any): void {
    window.sessionStorage.removeItem(USER_KEY);
    window.sessionStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  public saveToken(token: string): void {
    window.sessionStorage.removeItem(TOKEN_KEY);
    window.sessionStorage.setItem(TOKEN_KEY, token);
  }

  public getToken(): string | null {
    return window.sessionStorage.getItem(TOKEN_KEY);
  }

  public getUser(): any {
    const user = window.sessionStorage.getItem(USER_KEY);
    if (user) {
      return JSON.parse(user);
    }

    return null;
  }

  public isTokenExpired(): boolean {
    const user = this.getUser();
    if (!user || !user.token) return true;

    const decoded: any = jwtDecode(user.token,{header: true});
    if (decoded.exp === undefined) return false;
    
    const date = new Date(0); 
    date.setUTCSeconds(decoded.exp);
    return date.valueOf() <= new Date().valueOf();
  }

  public isLoggedIn(): boolean {
    const user = window.sessionStorage.getItem(USER_KEY);
    const token = window.sessionStorage.getItem(TOKEN_KEY);
    if (user) {
      return true;
    }

    return false;
  }
}
