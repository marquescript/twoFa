import { Injectable } from "@nestjs/common";
import { AsyncLocalStorage } from "async_hooks";

interface RequestStore {
    correlationId: string
}

@Injectable()
export class RequestStorageService {

    private readonly storage = new AsyncLocalStorage<RequestStore>()

    run(store: RequestStore, callback: () => void) {
        return this.storage.run(store, callback)
    }

    getCorrelationId() {
        return this.storage.getStore()?.correlationId
    }
}