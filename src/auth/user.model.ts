
class User {
    id: string;
    email: string;
    name: string;
    password: string;
    twoFaEnabled: boolean;
    twoFaSecret?: string;
    backupCodes: string[];
    createdAt?: Date;
    updatedAt?: Date;

    constructor(user: Partial<User>) {
        Object.assign(this, user);
    }
}

export default User;